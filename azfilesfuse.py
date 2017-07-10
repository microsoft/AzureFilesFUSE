#!/usr/bin/env python
from __future__ import print_function, absolute_import, division

import logging
import logging.handlers
import requests
from dateutil import parser
from sys import argv, exit
import sys
from time import time
import os
import stat
from fuse import FUSE, FuseOSError, Operations, LoggingMixIn, fuse_get_context
import errno
from errno import ENOENT
import io
import traceback
from collections import defaultdict, namedtuple
from time import time
import azure.storage.file as file
from azure.common import AzureMissingResourceHttpError, AzureConflictHttpError

import platform
import urllib.parse
#import ptvsd
#ptvsd.enable_attach(secret='my_secret')

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

class AzureFiles(LoggingMixIn, Operations):

    #_fd = 0
    #_freed_fd_list = []

    #File = namedtuple("File", ["path", "bytes", "dirty"], verbose=False, rename=False)

    '''
    A FUSE File Sytem for using Azure Files with a SAS token for connecting
    '''
    def __init__(self, azure_storage_account_name, azure_file_share_name, sas_token):
        LoggingMixIn.log.addHandler(console_handler)

        logger.info("Initializing AzureFiles Fuse Driver Implementation:%s %s", azure_storage_account_name, azure_file_share_name)
        self._azure_storage_account_name = azure_storage_account_name
        self._azure_file_share_name = azure_file_share_name
        self._sas_token = sas_token
        self._files_service = file.FileService(self._azure_storage_account_name, sas_token=self._sas_token)

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
        logger.info("create operation begin: path:{!r} mode:{}".format(path, mode))
        try:
            if not path:
                raise FuseOSError(errno.EINVAL)

            directory, filename = self._get_separated_path(path)
            self._files_service.create_file(self._azure_file_share_name, directory, filename, 0)

            logger.debug("create operation end: path:{!r} mode:{}".format(path, mode))
            return 0;

        except Exception as e:
            logger.exception("create operation exception: path:{!r} mode:{} exception:{}".format(path, mode, e))
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
        logger.info("getattr operation begin: path:{!r} fh:{}".format(path, fh))
        try:
            path = path.lstrip('/')
            logger.debug('getattr request: {}'.format(path))
            directory, filename = self._get_separated_path(path)
            st = {}
            uid, gid, pid = fuse_get_context()

            st['st_uid'] = uid
            st['st_gid'] = gid

            if path == '':
                st['st_mode'] = stat.S_IFDIR | 0o777
                st['st_nlink'] = 2
                return st
            
            try:
                properties = self._files_service.get_file_properties(
                    self._azure_file_share_name, directory, filename).properties
                item_type = 'file'
            except Exception:
                properties = self._files_service.get_directory_properties(
                    self._azure_file_share_name, path).properties
                item_type = 'dir'

            if item_type == 'dir':
                st['st_mode'] = stat.S_IFDIR | 0o777
                st['st_nlink'] = 2
            elif item_type == 'file':
                st['st_mode'] = stat.S_IFREG | 0o777
                st['st_nlink'] = 1
                st['st_size'] = properties.content_length
            else:
                raise FuseOSError(ENOENT)

            # Setting Modified Time
            try:
                st['st_mtime'] = properties.last_modified.timestamp()
            except Exception:
                logger.warning(
                    "getattr operation setting modified time failed: path:{!r} fh:{} st:{}".format(path, fh, st))

            # Setting Created Time
            try:
                st['st_ctime'] = properties.last_modified.timestamp()
            except Exception:
                logger.warning(
                    "getattr operation setting create time failed: path:{!r} fh:{} st:{}".format(path, fh, st))

            logger.debug("getattr operation end: path:{!r} fh:{} return:{}".format(path, fh, st))
            return st
        except Exception as e:
            # This log is noisy as it occurs if the file isn't found. Only uncomment for debugging.
            #logger.exception(
            #    "getattr operation exception: path:{!r} fh:{} exception:{}".format(path, fh, e))
            raise FuseOSError(ENOENT)   

    def mkdir(self, path, mode):
        '''
        creates directory at path with specific mode
        TODO: Mode is not respected at this time. Support could be added
        '''
        path = path.lstrip('/')
        logger.info("mkdir operation begin: path:{!r} mode:{}".format(path, mode))
        try:
            self._files_service.create_directory(
                self._azure_file_share_name, path, fail_on_exist=True)
            logger.debug("mkdir operation end: path:{!r} mode:{}".format(path, mode))
            return 0
        except Exception as e:
            # if we fail, it is most likely the file exists.
            logger.exception("mkdir operation exception: path:{!r} mode:{} exception:{}".format(path, mode, e))
            raise FuseOSError(errno.EEXIST) # directory exists or a file exists by the same name

    def read(self, path, size, offset, fh):
        '''
        read a file and return a buffer containing that area of the file
        '''
        logger.info("read operation begin: path:{!r} size:{} offset:{} fh:{}".format(path, size, offset, fh))
        try:
            dir_path, file_path = self._get_separated_path(path)
            data_to_return = self._files_service.get_file_to_bytes(
                self._azure_file_share_name, dir_path, file_path, offset, offset + size - 1).content

            #logger.info('read the following: "{}"'.format(data_to_return))
            logger.debug(
                "read operation end: path:{!r} size:{} offset:{} fh:{} data-to-return-length:{}".format(
                    path, size, offset, fh, len(data_to_return)))
            return data_to_return
        except Exception as e:
            logger.exception(
                "read operation exception: path:{!r} size:{} offset:{} fh:{} exception:{}".format(
                    path, size, offset, fh, e))
            raise e

    def readdir(self, path, fh):
        '''
        returns a directory listing for this directory
        '''
        path = path.lstrip('/')

        logger.info("readdir operation begin: path:{!r} fh:{}".format(path, fh))
        try:
            directory_listing = self._files_service.list_directories_and_files(
                self._azure_file_share_name, path)

            readdir_return = ['.', '..']
            readdir_return.extend([i.name for i in directory_listing])
            logger.debug(
                "readdir operation end: path:{!r} fh:{} return:{}".format(path, fh, readdir_return))
            return readdir_return
        except Exception as e:
            logger.exception(
                "readdir operation exception: path:{!r} fh:{} exception:{}".format(path, fh, e))
            raise FuseOSError(errno.ENOTDIR)

    def rename(self, old, new):
        """
        Rename a file or directory.
        TODO: Currently this implementation does not support renaming directories. Support needed.
        """
        logger.info("rename operation begin: old:{} new:{}".format(old, new))
        try:
            old_path = old.strip('/')
            new_path = new.strip('/')

            if new_path == old_path:
                # file exists at path. Would cause name collision
                raise FuseOSError(errno.EALREADY)

            self._rename(old_path, new_path, self._discover_item_type(old_path))
            logger.debug("rename operation end: old:{} new:{}".format(old, new))
            return 0
        except Exception as e:
            logger.exception(
                "rename operation exception: old:{} new:{} exception:{}".format(old, new, e))
            raise e

    def _rename(self, old_location, new_location, item_type):
        logger.debug('_rename - old:{} new:{} type:{}'.format(old_location, new_location, item_type))
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
        else:
            raise ValueError("item_type must be 'file' or 'directory'")

    def rmdir(self, path):
        '''
        removes a directory at specified path
        '''
        logger.info("rmdir operation begin: path:{!r}".format(path))
        try:

            path = path.strip('/')
            try:
                self._files_service.delete_directory(self._azure_file_share_name, path)
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

            logger.debug("rmdir operation end: path:{!r}".format(path))
        except Exception as e:
            logger.exception(
                "rmdir operation exception: path:{!r} exception:{}".format(path, e))
            raise e

    def unlink(self, path):
        '''
        Delete file.
        '''
        logger.info("unlink operation begin: path:{!r}".format(path))
        try:
            path = path.strip('/')
            directory, filename = self._get_separated_path(path)
            self._files_service.delete_file(self._azure_file_share_name, directory, filename)
            logger.debug("unlink operation end: path:{!r}".format(path))
            return 0
        except Exception as e:
            logger.exception("unlink operation exception: path:{!r} exception:{}".format(path, e))
            raise e

    def write(self, path, data, offset, fh):
        '''
        write
        '''
        logger.info("write operation begin: path:{!r} len(data):{} offset:{} fh:{}".format(path, len(data), offset, fh))
        try:
            path = path.lstrip('/')
            directory, filename = self._get_separated_path(path)
            f = self._files_service.get_file_properties(self._azure_file_share_name, directory, filename)
            file_length = f.properties.content_length 
            if offset < 0 or offset > file_length:
                logger.debug("write operation offset negative or exceeds file length: path:{!r} len(data):{} offset:{} fh:{}".format(path, len(data), offset, fh))
                raise FuseOSError(errno.EINVAL)
            # write the data at the range adding old data to the front and back of it.
            data_length = len(data)

            # update range fails if the file isn't as long as the range
            if file_length < offset + data_length:
                self._files_service.resize_file(self._azure_file_share_name, directory, filename, offset + data_length)

            # update the range specified by this write.
            self._files_service.update_range(self._azure_file_share_name, directory, filename, data, start_range=offset, end_range=offset+len(data)-1)

            # TODO: if we ever try to cache attrs, we would have to update the st_mtime.

            logger.debug("write operation end: path:{!r} len(data):{} offset:{} fh:{} return-data-length:{}".format(path, len(data), offset, fh, data_length))
            return data_length
        except Exception as e:
            logger.exception("write operation exception: path:{!r} len(data):{} offset:{} fh:{} exception:{}".format(path, len(data), offset, fh, e))
            raise e

    def truncate(self, path, length, fh=None):
        '''
        Truncate or extend the given file so that it is precisely size bytes long.
        See truncate(2) for details. This call is required for read/write filesystems,
        because recreating a file will first truncate it.
        '''
        logger.info("truncate operation begin: path:{!r} length:{} fh:{}".format(path, length, fh))
        # length must be positive
        if length < 0:
            raise FuseOSError(errno.EINVAL)
        try:
            path = path.lstrip('/')
            directory, filename = self._get_separated_path(path)
            self._files_service.resize_file(self._azure_file_share_name, directory, filename, length)
        except Exception as e:
            logger.exception("truncate operation exception: path:{!r} length:{} fh:{} e:{}".format(path, length, fh, e))
            raise e
        finally:
            logger.debug("truncate operation end: path:{!r} length:{} fh:{}".format(path, length, fh))

    
    def chmod(self, path, mode):
        '''
        chmod. This command is a NOP right now. 
        If it is missing this is interpreted as a read-only file system though.
        '''
        logger.info("chmod operation: path:{!r} mode:{}".format(path, mode))
        return
        
    def chown(self, path, uid, gid):
        '''
        chown. This command is a NOP right now.
        If it is missing this is interpreted as a read-only file system though.
        '''
        logger.info("chown operation: path:{!r} uid:{} gid:{}".format(path, uid, gid))
        return
        
if __name__ == '__main__':
    import syslog
    try:
        logger.info("Starting Azure Files Fuse Driver")
        if len(argv) == 2:
            # read file in from disk as specified, then pipe them into the arg list for below
            scriptargsfile = argv[1]
            logger.info("Starting Azure Files Fuse Driver using args file:{}".format(scriptargsfile))
            with open(scriptargsfile) as f:
                argsFromFile = f.readline().rstrip()
                splitArgs = argsFromFile.split(' ')
                argv = argv[0:1] + splitArgs
            logger.info("Removing args file after getting args")
            try:
                os.remove(scriptargsfile)
            except Exception as e:
                logger.error("Failed to remove fuseArgs file:{}".format(e))

        if len(argv) != 5:
            print('usage: {} <azure_storage_account_name> <azure_file_share_name> <sas_token> <mount_point>'.format(argv[0]))
            syslog.syslog(syslog.LOG_ERR, "Arguments to Python Fuse Driver Bad: {}".format(argv))
            exit(1)

        syslog.syslog("fuse = FUSE(AzureFiles({}, {}, {}), {}, foreground=True, nothreads=True)".format(argv[1], argv[2], argv[3], argv[4]))
        logging.basicConfig(level=LOGGING_LEVEL)
        fuse = FUSE(AzureFiles(argv[1], argv[2], argv[3]), argv[4], foreground=True, nothreads=True, debug=False)
    except Exception as e:
        logger.error("Python Fuse Top-Level Exception: {}".format(e))
        logger.error("Python Fuse Top-Level Trace Exception: {}".format(traceback.format_exc()))

