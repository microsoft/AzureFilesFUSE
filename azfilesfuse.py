#!/usr/bin/env python
from __future__ import absolute_import, division, print_function

import concurrent.futures
import contextlib
import errno
import io
import logging
import logging.handlers
import os
import platform

import stat
import sys
import threading
import traceback
import urllib.parse
import uuid

from collections import defaultdict, deque, namedtuple
from errno import ENOENT
from sys import argv, exit
from time import time

import azure.storage.file as file
import requests
from azure.common import (AzureConflictHttpError, AzureHttpError,
                          AzureMissingResourceHttpError)
from azure.storage.file import models
from dateutil import parser
from fuse import FUSE, FuseOSError, LoggingMixIn, Operations, fuse_get_context
from requests import Session

executor = concurrent.futures.ThreadPoolExecutor(4)

#import ptvsd
#ptvsd.enable_attach(secret='my_secret')

# This controls the minimum level that is logged.
# Available levels are: NOTSET, DEBUG, INFO, WARNING, ERROR, CRITICAL.
LOGGING_LEVEL=logging.INFO
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

logger = logging.getLogger("AzureFiles_FuseDriver")
logger.setLevel(LOGGING_LEVEL)
logger.addHandler(console_handler)

if platform.system() is not 'Windows':
    syslog_handler = logging.handlers.SysLogHandler(address = '/dev/log')
    formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
    syslog_handler.setFormatter(formatter)
    logger.addHandler(syslog_handler)

class WriteInfo(object):
    '''Used to track writes to a file and coalesce them into a single write into
    Azure files.  We'll track the destination and whether or not the write has
    been processed.  We'll then combine sequential writes.'''
    def __init__(self, files, directory, filename, offset, data, orig_path):
        self.files = files
        self.directory = directory
        self.filename = filename
        self.offset = offset
        self.data = data
        self.processing = False
        self.orig_path = orig_path

    def write(self):
        try:
            with self.files.file_cache[self.orig_path].append_write_lock:
                self.processing = True
            with self.files.file_cache[self.orig_path].write_lock:
                max_size = self.files.file_cache[self.orig_path].max_size
                data_length = len(self.data)
                computed_content_length = self.offset + data_length
                if max_size < computed_content_length:
                    f = self.files._files_service.get_file_properties(self.files._azure_file_share_name,
                                                            self.directory, self.filename)
                    file_length = f.properties.content_length

                    if file_length < computed_content_length:
                        self.files._files_service.resize_file(self.files._azure_file_share_name, self.directory, self.filename, computed_content_length)
                        self.files.file_cache[self.orig_path].max_size = computed_content_length
                        cached = self.files._get_cached_dir(self.directory, False)
                        if cached is not None:
                            file = cached.get(self.filename)
                            if cached is not None:
                                logger.debug("Updating content length to computed length:%s", computed_content_length)
                                file.properties.content_length = computed_content_length
                            else:
                                props = models.FileProperties()
                                props.content_length = computed_content_length
                                logger.debug("Updating cached content length:%s", props.content_length)
                                cached[self.filename] = models.File(self.filename, None, props)

                # update the range specified by this write.
                #logger.debug('updating %s range %d to %d', path, self.offset, self.offset+data_length-1)
                self.files._files_service.update_range(self.files._azure_file_share_name, self.directory, self.filename, self.data, start_range=self.offset, end_range=self.offset+data_length-1)

        except Exception as e:
            logger.warning('error writing %s', str(e))

class FileCache:
    '''Tracks information that we've cached locally about an individual file.  Currently we track writes and use a couple
    of locks to protect that as well as the max file size that we've resized to'''
    def __init__(self):
        self.write_lock = threading.Lock()
        self.append_write_lock = threading.Lock()
        self.max_size = 0
        self.writes = deque()
        self.pending_writes = set()

class AzureFiles(LoggingMixIn, Operations):

    '''
    A FUSE File Sytem for using Azure Files with a SAS token for connecting
    '''
    def __init__(self, azure_storage_account_name, azure_file_share_name, sas_token):
        LoggingMixIn.log.addHandler(console_handler)

        logger.info("Initializing AzureFiles Fuse Driver Implementation:%s %s", azure_storage_account_name, azure_file_share_name)
        self._azure_storage_account_name = azure_storage_account_name
        self._azure_file_share_name = azure_file_share_name
        self._sas_token = sas_token
        self._files_service = file.FileService(self._azure_storage_account_name, sas_token=self._sas_token, request_session=Session())
        
        self.writes = deque()

        self.dir_cache = {}

        self.file_cache = defaultdict(FileCache)

    def _get_separated_path(self, path):
        path = path.lstrip('/')
        return (os.path.dirname(path), os.path.basename(path))

    def _discover_item_type(self, item_path):
        try:
            self._files_service.get_directory_metadata(self._azure_file_share_name, item_path)
            return 'directory'
        except AzureMissingResourceHttpError:
            try:
                # if this fails, it is likely a file. Let's try for a file.
                path_dir, path_file = self._get_separated_path(item_path)
                self._files_service.get_file_metadata(self._azure_file_share_name, path_dir, path_file)
                return 'file'
            except AzureMissingResourceHttpError:
                # if that also fails, we must have a not found.
                raise FuseOSError(errno.ENOENT)

    # FUSE Methods
    def create(self, path, mode):
        '''
        create a file at the specified path with specific access mode (chmod)
        TODO: Mode is not respected at this time. Support could be added
        '''
        path = path.lstrip('/')
        logger.debug("create operation begin: path:%r  mode:%s", path, mode)
        try:
            if not path:
                raise FuseOSError(errno.EINVAL)

            directory, filename = self._get_separated_path(path)
            self._files_service.create_file(self._azure_file_share_name, directory, filename, 0)
            cached = self._get_cached_dir(directory, False)
            if cached is not None:
                props = models.FileProperties()
                props.content_length = 0
                cached[filename] = models.File(filename, None, props)
            logger.debug("create operation end: path:%r mode:%s", path, mode)
            return 0;

        except Exception as e:
            logger.exception("create operation exception: path:%r mode:%s exception:%s", path, mode, e)
            raise FuseOSError(ENOENT)
    
    def getattr(self, path, fh=None):
        '''
        return file attributes
        st_atime   /* Time when file data last accessed.*/
        st_mode    /* inode protection mode */
        st_mtime   /* Time when file data last modified. */
        st_ctime   /* Time when file was created. */
        st_size    /* file size, in bytes */
        st_uid;    /* user-id of owner */
        st_gid;    /* group-id of owner */
        '''
        try:
            # because getattr returns size, we need to wait on writes to complete
            self.flush(path, fh)
            logger.debug("flush done")

            path = path.lstrip('/')
            directory, filename = self._get_separated_path(path)
            st = {}
            uid, gid, pid = fuse_get_context()

            st['st_uid'] = uid
            st['st_gid'] = gid


            if path == '':
                st['st_mode'] = stat.S_IFDIR | 0o755
                st['st_nlink'] = 2
                return st
            
            directory_listing = self._get_cached_dir(directory)
            item = directory_listing.get(filename)
            if item is None:
                logger.debug("item doesn't exist: path:%r fh:%s return:%s", path, fh, st)
                raise FuseOSError(ENOENT)

            if isinstance(item, models.Directory):
                st['st_mode'] = stat.S_IFDIR | 0o755
                st['st_nlink'] = 2
                properties = self._files_service.get_directory_properties(
                    self._azure_file_share_name, path).properties
            else:
                st['st_mode'] = stat.S_IFREG | 0o644
                st['st_nlink'] = 1
                st['st_size'] = item.properties.content_length
                properties = self._files_service.get_file_properties(
                    self._azure_file_share_name, directory, filename).properties
            
            # Setting Modified Time
            try:
                st['st_mtime'] = properties.last_modified.timestamp()
            except Exception:
                logger.warning(
                    "getattr operation setting modified time failed: path:%r fh:%d st:%s", path, fh, st)
            
            # Setting Created Time
            try:
                st['st_ctime'] = properties.last_modified.timestamp()
            except Exception:
                logger.warning(
                    "getattr operation setting create time failed: path:%r fh:%d st:%s", path, fh, st)

            logger.debug("getattr operation end: path:%r fh:%s return:%s", path, fh, st)
            return st
        except Exception as e:
            # This log is noisy as it occurs if the file isn't found. Only uncomment for debugging.
            #logger.exception(
            #    "getattr operation exception: path:%r fh:%d exception:%s", path, fh, e)
            raise FuseOSError(ENOENT)

    def mkdir(self, path, mode):
        '''
        creates directory at path with specific mode
        TODO: Mode is not respected at this time. Support could be added
        '''
        path = path.lstrip('/')
        logger.debug("mkdir operation begin: path:%r mode:%s", path, mode)
        try:
            self._files_service.create_directory(
                self._azure_file_share_name, path, fail_on_exist=True)
            directory, filename = self._get_separated_path(path)
            cached = self._get_cached_dir(directory, False)
            if cached is not None:
                cached[filename] = models.Directory(filename)
                logger.debug("mkdir operation: %s %s", filename, cached)

            logger.debug("mkdir operation end: path:%r mode:%s", path, mode)
            return 0
        except AzureHttpError as ahe:
            logger.exception("mkdir operation azurehttperror exception: path:%r mode:%s exception:%s", path, mode, ahe)

            if [i for i in ahe.args if 'The specified parent path does not exist' in i]:
                raise FuseOSError(errno.ENOENT)
            else:
                # if we fail, it is most likely the file exists. 
                raise FuseOSError(errno.EEXIST) # directory exists or a file exists by the same name
        except Exception as e:
            logger.exception("mkdir operation exception: path:%r mode:%s exception:%s", path, mode, e)
            raise e

    def read(self, path, size, offset, fh):
        '''
        read a file and return a buffer containing that area of the file
        '''
        logger.debug("read operation begin: path:%r size:%s offset:%s fh:%s", path, size, offset, fh)
        self.flush(path)
        try:
            dir_path, file_path = self._get_separated_path(path)
            try:
                data_to_return = self._files_service.get_file_to_bytes(
                    self._azure_file_share_name, dir_path, file_path, offset, offset + size - 1).content
            except AzureHttpError as ahe:
                if [i for i in ahe.args if 'InvalidRange' in i]:
                    logger.debug("read operation bad range. Offset provided must have been larger than file. path:%r size:%d offset:%d fh:%d exception:%s", path, size, offset, fh, ahe)
                    return FuseOSError(errno.EINVAL)
                else:
                    raise ahe

            logger.debug(
                "read operation end: path:%r size:%s offset:%s fh:%s data-to-return-length:%s",
                    path, size, offset, fh, len(data_to_return))
            return data_to_return

        except Exception as e:
            logger.exception(
                "read operation exception: path:%r size:%s offset:%s fh:%s exception:%s",
                    path, size, offset, fh, e)
            raise e

    def _get_cached_dir(self, path, force = True):
        cached = self.dir_cache.get(path)
        if (cached is None or cached[1] + 5 < time()) and force:
            directory_listing = { item.name:item for item in
                                  self._files_service.list_directories_and_files(self._azure_file_share_name, path)
            }
            self.dir_cache[path] = directory_listing, time()
            return directory_listing
        if cached is None:
            return None
        else:
            return cached[0]

    def _clear_dir_cache(self, path, reason):
        with contextlib.suppress(KeyError):
            del self.dir_cache[path]

    def readdir(self, path, fh):
        '''
        returns a directory listing for this directory
        '''
        path = path.lstrip('/')

        logger.debug("readdir operation begin: path:%r fh:%s", path, fh)
        try:
            directory_listing = self._get_cached_dir(path)

            readdir_return = ['.', '..']
            readdir_return.extend(directory_listing.keys())
            logger.debug(
                "readdir operation end: path:%r fh:%s return:%s", path, fh, readdir_return)
            return readdir_return
        except Exception as e:
            logger.exception(
                "readdir operation exception: path:%r fh:%s exception:%s", path, fh, e)
            raise FuseOSError(errno.ENOTDIR)

    def rename(self, old, new):
        """
        Rename a file or directory.
        TODO: Currently this implementation does not support renaming directories. Support needed.
        """
        logger.debug("rename operation begin: old:%r new:%r", old, new)
        try:
            old_orig_path = old
            old_path = old.strip('/')
            new_path = new.strip('/')

            if new_path == old_path:
                # file exists at path. Would cause name collision
                raise FuseOSError(errno.EALREADY)

            if new_path.lower() == old_path.lower():
                # Azure Files is case insensitive, but case preserving
                # Do the rename by moving to an intermediate file
                # So we can create a file with different casing.
                temporary_path = "{}-rename-{}".format(old, uuid.uuid4())
                self.rename(old, temporary_path)
                self.rename(temporary_path, new)
                return

            with self.file_cache[old_orig_path].write_lock:
                new_length = self._rename(old_path, new_path, self._discover_item_type(old_path))
                self.file_cache[old_orig_path].max_size = 0
                if new_length is None:
                    self._clear_dir_cache(self._get_separated_path(old_path)[0],'rename old')
                    self._clear_dir_cache(self._get_separated_path(new_path)[0],'rename new')
                else:
                    directory, filename = self._get_separated_path(old_path)
                    cached = self._get_cached_dir(directory, False)
                    if cached is not None:
                        with contextlib.suppress(KeyError):
                            del cached[filename]
                    directory, filename = self._get_separated_path(new_path)
                    cached = self._get_cached_dir(directory, False)
                    if cached is not None:
                        with contextlib.suppress(KeyError):
                            if new_length is None:
                                cached[filename] = models.Directory(filename)
                            else:
                                props = models.FileProperties()
                                props.content_length = new_length
                                cached[filename] = models.File(filename, None, props)
            logger.debug("rename operation end: old:%r new:%r", old, new)
            return 0
        except Exception as e:
            logger.exception(
                "rename operation exception: old:%r new:%r exception:%s", old, new, e)
            raise e

    def _rename(self, old_location, new_location, item_type):
        logger.debug('_rename - old:%s new:%s type:%s', old_location, new_location, item_type)
        old_location = old_location.strip('/')
        new_location = new_location.strip('/')
        if item_type == 'directory':
            self._files_service.create_directory(self._azure_file_share_name, new_location)
            # we need to recurse for each object in the directory
            for i in self._files_service.list_directories_and_files(self._azure_file_share_name, old_location):
                old_path = os.path.join(old_location, i.name)
                new_path = os.path.join(new_location, i.name)
                if type(i) is file.models.File:
                    self._rename(old_path, new_path, 'file')
                elif type(i) is file.models.Directory:
                    self._rename(old_path, new_path, 'directory')
                else:
                    raise ValueError("item_type must be directory or file. unexpected type: {}".format(type(i)))
            self._files_service.delete_directory(self._azure_file_share_name, old_location)
        elif item_type =='file':
            # rename this object.
            old_path_dir, old_path_file = self._get_separated_path(old_location)
            new_path_dir, new_path_file = self._get_separated_path(new_location)

            file_contents = self._files_service.get_file_to_bytes(self._azure_file_share_name, old_path_dir, old_path_file).content
            self._files_service.create_file_from_bytes(self._azure_file_share_name, new_path_dir, new_path_file, file_contents)

            self._files_service.delete_file(self._azure_file_share_name, old_path_dir, old_path_file)

            return len(file_contents)
        else:
            raise ValueError("item_type must be 'file' or 'directory'")

    def rmdir(self, path):
        '''
        removes a directory at specified path
        '''
        logger.debug("rmdir operation begin: path:%r", path)
        try:

            path = path.strip('/')
            try:
                self._files_service.delete_directory(self._azure_file_share_name, path)
                directory, filename = self._get_separated_path(path)
                cached = self._get_cached_dir(directory, False)
                if cached is not None:
                    with contextlib.suppress(KeyError):
                        del cached[filename]
            except AzureConflictHttpError as error:
               logger.debug("rmdir operation: path:{!r} directory not empty")
               raise FuseOSError(errno.ENOTEMPTY)

            # TODO: we may want to handle not found, not empty, not allowed.
            # # check response code to see if we should return a more specific error
            # if response.status_code == requests.codes.not_found:
            #     raise FuseOSError(errno.ENOENT)
            # if response.status_code == requests.codes.bad_request:
            #     raise FuseOSError(errno.ENOTEMPTY)
            # elif response.status_code == requests.codes.forbidden or response.status_code == requests.codes.unauthorized:
            #     raise FuseOSError(errno.EACCES)
            # elif not response.status_code == requests.codes.ok:
            #     logger.exception("rmdir operation had bad response status code:{}".format(response.status_code))
            #     raise FuseOSError(errno.ENOENT)

            logger.debug("rmdir operation end: path:%r", path)
        except Exception as e:
            logger.exception(
                "rmdir operation exception: path:%r exception:%s", path, e)
            raise e

    def unlink(self, path):
        '''
        Delete file.
        '''
        logger.debug("unlink operation begin: path:%r", path)
        self.flush(path)
        try:
            orig_path = path
            path = path.strip('/')
            directory, filename = self._get_separated_path(path)
            with self.file_cache[orig_path].write_lock:
                self._files_service.delete_file(self._azure_file_share_name, directory, filename)
                logger.debug('unlink resetting to 0 %r', orig_path)
                self.file_cache[orig_path].max_size = 0
            cached = self._get_cached_dir(directory, False)
            if cached is not None:
                with contextlib.suppress(KeyError):
                    del cached[filename]
            logger.debug("unlink operation end: path:%r", path)
            return 0
        except AzureHttpError as ahe:
            if [i for i in ahe.args if 'The specified resource does not exist' in i]:
                raise FuseOSError(errno.ENOENT)
            logger.exception("unlink operation AHE exception: path:%r exception:%s", path, ahe)
            raise ahe
        except Exception as e:
            logger.exception("unlink operation exception: path:%r exception:%s", path, e)
            raise e

    def write(self, path, data, offset, fh):
        '''
        write
        '''
        logger.debug("write operation begin: path:%r len(data):%d offset:%d fh:%d", path, len(data), offset, fh)
        try:
            orig_path = path
            path = path.lstrip('/')
            directory, filename = self._get_separated_path(path)
            if offset < 0:
                logger.debug("write operation offset negative or exceeds file length: path:%r len(data):%d offset:%d fh:%d", path, len(data), offset, fh)
                raise FuseOSError(errno.EINVAL)
            # write the data at the range adding old data to the front and back of it.
            data_length = len(data)
            

            # Take the write lock to see if we can coalesce
            with self.file_cache[orig_path].append_write_lock:
                found = False
                if self.file_cache[orig_path].writes:
                    last = self.file_cache[orig_path].writes[-1]
                    if (not last.processing and
                        (last.offset + len(last.data)) == offset and
                        len(last.data) + len(data) < file.FileService.MAX_RANGE_SIZE):
                        # let's piggy back on this write...
                        last.data += data
                        found = True

                if not found:
                    wi = WriteInfo(self, directory, filename, offset, data, orig_path)
                    self.file_cache[orig_path].writes.append(wi)
                    future = executor.submit(wi.write)
                    self.file_cache[orig_path].pending_writes.add(future)
                    def done(future):
                        self.file_cache[orig_path].pending_writes.remove(future)
                    future.add_done_callback(done)
          
            # TODO: if we ever try to cache attrs, we would have to update the st_mtime.

            logger.debug("write operation end: path:%r len(data):%d offset:%d fh:%d return-data-length:%d", path, len(data), offset, fh, data_length)
            return data_length
        except AzureHttpError as ahe:
            if [i for i in ahe.args if 'ShareSizeLimitReached' in i]:
                logger.exception("write operation AzureHTTPError. ShareSizeLimitReached path:%r len(data):%d offset:%d fh:%d exception:%s", path, len(data), offset, fh, ahe)
                raise FuseOSError(errno.ENOSPC)
            
            logger.exception("write operation AzureHTTPError: path:%r len(data):%d offset:%d fh:%d exception:%s", path, len(data), offset, fh, ahe)
            raise ahe
        except Exception as e:
            logger.debug("write operation exception: path:%r len(data):%d offset:%d fh:%d exception:%s", path, len(data), offset, fh, e)
            raise e

    def flush(self, path, fh = None):
        w = concurrent.futures.wait(self.file_cache[path].pending_writes)
    
    def release(self, path, fh):
        self.file_cache[path].max_size = 0

    def truncate(self, path, length, fh=None):
        '''
        Truncate or extend the given file so that it is precisely size bytes long.
        See truncate(2) for details. This call is required for read/write filesystems,
        because recreating a file will first truncate it.
        '''
        logger.debug("truncate operation begin: path:%r length:%d fh:%d", path, length, fh)
        # length must be positive
        if length < 0:
            raise FuseOSError(errno.EINVAL)
        try:
            orig_path = path
            path = path.lstrip('/')
            directory, filename = self._get_separated_path(path)
            with self.file_cache[orig_path].write_lock:
                self._files_service.resize_file(self._azure_file_share_name, directory, filename, length)
                self.file_cache[orig_path].max_size = length
                cached = self._get_cached_dir(directory, False)
                if cached is not None:
                    file = cached.get(filename)
                    if cached is not None:
                        file.properties.content_length = length
                    else:
                        props = models.FileProperties()
                        props.content_length = length
                        cached[filename] = models.File(filename, None, props)
        except Exception as e:
            logger.exception("truncate operation exception: path:%r length:%d fh:%d e:%s", path, length, fh, e)
            raise e
        finally:
            logger.debug("truncate operation end: path:%r length:%d fh:%d", path, length, fh)

    
    def chmod(self, path, mode):
        '''
        chmod. This command is a NOP right now.
        If it is missing this is interpreted as a read-only file system though.
        '''
        logger.debug("chmod operation: path:%r mode:%s", path, mode)
        return
        
    def chown(self, path, uid, gid):
        '''
        chown. This command is a NOP right now.
        If it is missing this is interpreted as a read-only file system though.
        '''
        logger.debug("chown operation: path:%r uid:%s gid:%s", path, uid, gid)
        return
        
if __name__ == '__main__':
    import syslog
    try:
        logger.info("Starting Azure Files Fuse Driver")
        if len(argv) == 2:
            # read file in from disk as specified, then pipe them into the arg list for below
            scriptargsfile = argv[1]
            logger.info("Starting Azure Files Fuse Driver using args file:%s", scriptargsfile)
            with open(scriptargsfile) as f:
                argsFromFile = f.readline().rstrip()
                splitArgs = argsFromFile.split(' ')
                argv = argv[0:1] + splitArgs
            logger.info("Removing args file after getting args")
            try:
                os.remove(scriptargsfile)
            except Exception as e:
                logger.error("Failed to remove fuseArgs file:%s", e)

        if len(argv) != 5:
            print('usage: {} <azure_storage_account_name> <azure_file_share_name> <sas_token> <mount_point>'.format(argv[0]))
            syslog.syslog(syslog.LOG_ERR, "Arguments to Python Fuse Driver Bad: {}".format(argv))
            exit(1)

        syslog.syslog("fuse = FUSE(AzureFiles({}, {}, {}), {}, foreground=True, nothreads=True)".format(argv[1], argv[2], argv[3], argv[4]))
        logging.basicConfig(level=LOGGING_LEVEL)
        fuse = FUSE(AzureFiles(argv[1], argv[2], argv[3]), argv[4], foreground=True, nothreads=True, debug=False)
    except Exception as e:
        logger.error("Python Fuse Top-Level Exception: %s", e)
        logger.error("Python Fuse Top-Level Trace Exception: %s", traceback.format_exc())
