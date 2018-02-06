import unittest
from unittest import mock
from collections import namedtuple
import ctypes
import ctypes.util
import platform
import requests
import json
import time
import vcr
import azure.storage.file as file
from azure.storage.file import models
import os

# USEFUL LINKS FOR THESE TESTS:
#     ERRNO http://man7.org/linux/man-pages/man3/errno.3.html
#     requests status codes:https://github.com/kennethreitz/requests/blob/5524472cc76ea00d64181505f1fbb7f93f11cc2b/requests/status_codes.py
#     http codes: https://en.wikipedia.org/wiki/List_of_HTTP_status_codes

# mock out finding the fuse library and loading it so we can load the driver.
# We don't actually use this bit anyway in testing.
# TODO: figure out how to have the mock only happen for find_library('fuse')
# mock should only occur for CDLL(_libfuse_path).  libfuse_path will be 'fake'
original_find_library = ctypes.util.find_library
original_cdll = ctypes.CDLL
def find_library_mock(value):
    if value == 'fuse':
        return 'fake'
    return original_find_library(value)

Contents = namedtuple('Contents', 'uid gid pid')

class fake_fuse_context():
    def __init__(self):
        pass
    contents = Contents(uid=123, gid=123, pid=123)

class fake_fuse_obj(object):
    def __init__(self):
        setattr(self, 'fuse_get_context', fake_fuse_context)
        setattr(self.fuse_get_context, 'restype', lambda: None)

def cdll_mock(*args, **kwargs):
    if args[0] is 'fake':
        return fake_fuse_obj()
    return original_cdll(*args, **kwargs)
with mock.patch.object(ctypes.util, 'find_library', side_effect=find_library_mock):
    with mock.patch('ctypes.CDLL',  side_effect=cdll_mock) as ma:
        with mock.patch.object(platform, 'system', side_effect=['Linux', 'Windows']):
            #cdll.side_effect = cdll_mock
            import azfilesfuse


class Test_azfilesfuse(unittest.TestCase):
    STORAGE_ACCOUNT_NAME='crwilcoxmsftplayground'
    STORAGE_ACCOUNT_SHARE='fusetests'
    STORAGE_ACCOUNT_SAS_TOKEN='None'

    def setUp(self):
        # TODO: Verify Settings provided
        env_name = os.environ.get("azfilesfuse_test_accountname", None)
        if env_name is not None:
            self.STORAGE_ACCOUNT_NAME = env_name
        if self.STORAGE_ACCOUNT_NAME is None:
            raise Exception("STORAGE_ACCOUNT_NAME variable necessary for running tests not set.")

        env_share = os.environ.get("azfilesfuse_test_accountshare", None)
        if env_share is not None:
            self.STORAGE_ACCOUNT_SHARE = env_share
        if self.STORAGE_ACCOUNT_SHARE is None:
            raise Exception("STORAGE_ACCOUNT_SHARE variable necessary for running tests not set.")

        env_sas_token = os.environ.get("azfilesfuse_test_accountsastoken", None)
        if env_sas_token is not None:
            self.STORAGE_ACCOUNT_SAS_TOKEN = env_sas_token
        if self.STORAGE_ACCOUNT_SAS_TOKEN is None:
            raise Exception("STORAGE_ACCOUNT_SAS_TOKEN variable necessary for running tests not set.")
        
        # use the azure files sdk to verify before starting our tests the share is empty.
        self.azure_fs = file.FileService(self.STORAGE_ACCOUNT_NAME, sas_token=self.STORAGE_ACCOUNT_SAS_TOKEN.lstrip('?'))

        self.delete_files_and_directories_from_share()

        # need to import this after mocking up some of its components, or else
        # this will need to create the fuse class to be tested.
        # we also want to mock out things.  though we may do that per test.
        self.fuse_driver = azfilesfuse.AzureFiles(
            self.STORAGE_ACCOUNT_NAME, self.STORAGE_ACCOUNT_SHARE, self.STORAGE_ACCOUNT_SAS_TOKEN)
    
    def delete_files_and_directories_from_share(self, dirpath=''):
        dirpath = dirpath.lstrip('/')
        for f in self.azure_fs.list_directories_and_files(self.STORAGE_ACCOUNT_SHARE, dirpath):
            if type(f) is models.File:
                    path = dirpath + "/" + f.name.lstrip('/')
                    path = path.lstrip('/')
                    directory = os.path.dirname(path)
                    filename = os.path.basename(path)
                    self.azure_fs.delete_file(self.STORAGE_ACCOUNT_SHARE, directory, filename)
                    
            if type(f) is models.Directory:
                self.delete_files_and_directories_from_share(dirpath + "/" + f.name)
        if dirpath != '':
            self.azure_fs.delete_directory(self.STORAGE_ACCOUNT_SHARE, dirpath)

    #region Tests
    def test_create(self):
        self.fuse_driver.create('file.txt', 644)
        self.assertEqual(
            self.fuse_driver.readdir('.', None),
            ['.', '..', 'file.txt'])
        
        # TODO: failing but works fine under debugger
        #self.fuse_driver.create('file2.txt', 644)
        #self.assertEqual(
        #    self.fuse_driver.readdir('.', None),
        #    ['.', '..', 'file.txt', 'file2.txt'])

    
    def test_getattr(self,):
        self.azure_fs.create_file_from_bytes(self.STORAGE_ACCOUNT_SHARE, '', 'file.txt', b'test file content')
        self.azure_fs.create_directory(self.STORAGE_ACCOUNT_SHARE, 'dir')
        t = time.time()
        
        # {'st_ctime': 1504203454.0, 'st_gid': 123, 'st_mode': 33188, 
        #  'st_mtime': 1504203454.0, 'st_nlink': 1, 'st_size': 17, 'st_uid': 123}
        file_attr = self.fuse_driver.getattr('file.txt')
        self.assertTrue(abs(file_attr['st_ctime']-t) < 5, "ctime:{} walltime:{}".format(file_attr['st_ctime'], t))
        self.assertTrue(abs(file_attr['st_mtime']-t) < 5, "mtime:{} walltime:{}".format(file_attr['st_mtime'], t))
        del(file_attr['st_ctime'])
        del(file_attr['st_mtime'])
        self.assertDictEqual(file_attr, {'st_gid': 123, 'st_mode': 33188, 'st_nlink': 1, 'st_size': 17, 'st_uid': 123})

        # {'st_ctime': 1504203454.0, 'st_gid': 123, 'st_mode': 16877, 
        #  'st_mtime': 1504203454.0, 'st_nlink': 2, 'st_uid': 123}
        dir_attr = self.fuse_driver.getattr('dir')
        self.assertTrue(abs(dir_attr['st_ctime']-t) < 5, "ctime:{} walltime:{}".format(dir_attr['st_ctime'], t))
        self.assertTrue(abs(dir_attr['st_mtime']-t) < 5, "mtime:{} walltime:{}".format(dir_attr['st_mtime'], t))
        del(dir_attr['st_ctime'])
        del(dir_attr['st_mtime'])
        self.assertDictEqual(dir_attr, {'st_gid': 123, 'st_mode': 16877, 'st_nlink': 2, 'st_uid': 123})

    def test_mkdir(self):
        # dir succeeds
        res = self.fuse_driver.mkdir('random_dir', None)
        self.assertEqual(0, res)

        # test different error codes and that they result in exceptions
        # verify a failure related to the specified directory existing already
        with self.assertRaisesRegex(Exception, '\[Errno 17\] File exists'):
            res = self.fuse_driver.mkdir('random_dir', None)

        # verify trying to make subdir in non existent
        with self.assertRaisesRegex(Exception, '\[Errno 2\] No such file or directory'):
            res = self.fuse_driver.mkdir('dir_not_exist/badrequest', None)

    def test_open(self):
        fd = self.fuse_driver.open('file.txt', 'r')
        self.assertEqual(fd, 0)

    def test_read(self):
        self.azure_fs.create_file_from_bytes(self.STORAGE_ACCOUNT_SHARE, '', 'file.txt', b'test file content')

        # verify the data can be read and seeked
        fd = self.fuse_driver.open('file.txt', 'r')
        # length from beginning
        content = self.fuse_driver.read('file.txt', 17, 0, fd)
        self.assertEqual(content, b'test file content')
        # full length from beginning
        content = self.fuse_driver.read('file.txt', 3, 0, fd)
        self.assertEqual(content, b'tes')
        # offset
        content = self.fuse_driver.read('file.txt', 4, 5, fd)
        self.assertEqual(content, b'file')
        # test 0 length
        #content = self.fuse_driver.read('file.txt', 0, 0, fd)
        #self.assertEqual(content, b'')
        # test too much offset
        #content = self.fuse_driver.read('file.txt', 0, 100, fd)
        #self.assertEqual(content, b'')
        # test negative offset
        #content = self.fuse_driver.read('file.txt', 0, -1, fd)
        #self.assertEqual(content, b'')
        # test too much length
        content = self.fuse_driver.read('file.txt', 100, 0, fd)
        self.assertEqual(content, b'test file content')
        
        # test negative length
        #content = self.fuse_driver.read('file.txt', -1, 0, fd)
        #self.assertEqual(content, b'')

    def test_readdir(self):
        # TODO: Can't look at same directory twice as it will cache the dir.
        #response = self.fuse_driver.readdir('', None)
        #self.assertEqual(response, ['.', '..'])

        self.azure_fs.create_file(self.STORAGE_ACCOUNT_SHARE, '', 'file.txt', 0)
        self.azure_fs.create_directory(self.STORAGE_ACCOUNT_SHARE, 'Untitled Folder')
        self.azure_fs.create_directory(self.STORAGE_ACCOUNT_SHARE, 'Untitled Folder/subdir')
        self.azure_fs.create_file(self.STORAGE_ACCOUNT_SHARE, 'Untitled Folder', 'a.txt', 0)
        self.azure_fs.create_file(self.STORAGE_ACCOUNT_SHARE, 'Untitled Folder', 'b.txt', 0)

        response = self.fuse_driver.readdir('', None)
        # fuzzy match lists for sorted order differences.
        self.assertCountEqual(response, ['.', '..', 'Untitled Folder', 'file.txt'])

        response = self.fuse_driver.readdir('Untitled Folder', None)
        self.assertCountEqual(response, ['.', '..', 'subdir', 'a.txt', 'b.txt'])

    def test_rename(self):
        self.azure_fs.create_file_from_bytes(self.STORAGE_ACCOUNT_SHARE, '', 'file.txt', b'test file content')
        self.azure_fs.create_file_from_bytes(self.STORAGE_ACCOUNT_SHARE, '', 'file_exists2.txt', b'test file content')
        self.azure_fs.create_file_from_bytes(self.STORAGE_ACCOUNT_SHARE, '', 'file_renaming_exists.txt', b'test file content')

        self.azure_fs.create_directory(self.STORAGE_ACCOUNT_SHARE, 'dir')
        self.azure_fs.create_directory(self.STORAGE_ACCOUNT_SHARE, 'dir/direxists')
        self.azure_fs.create_directory(self.STORAGE_ACCOUNT_SHARE, 'dir/direxists2')
        self.azure_fs.create_directory(self.STORAGE_ACCOUNT_SHARE, 'dirrenamed')

        # rename a file
        self.fuse_driver.rename('file.txt', 'file_renamed.txt')
        
        # rename a dir
        self.fuse_driver.rename('dir/direxists', 'dir/dirrenamed')
        
        # test renaming directory to a new root path
        # in non-mocked test, it would make sense to test with both an existent
        # and non existent root
        self.fuse_driver.rename('dir/direxists2', 'dirrenamed/newrootpath')
        
        # TODO: test renaming file with conflict
        # with self.assertRaisesRegex(Exception, '\[Errno 17\] File exists'):
        #   self.fuse_driver.rename('file_renaming_exists.txt', 'file_exists2.txt')

        # test renaming file not found
        with self.assertRaisesRegex(Exception, '\[Errno 2\] No such file or directory'):
            self.fuse_driver.rename('fnf.txt', 'fnf2.txt')

    def test_rename_delete_odd_chars(self):
        self.azure_fs.create_file_from_bytes(self.STORAGE_ACCOUNT_SHARE, '', 'file.txt', b'test file content')
        self.azure_fs.create_directory(self.STORAGE_ACCOUNT_SHARE, 'dir')

        self.fuse_driver.rename('file.txt', 'file%20renamed.txt')
        self.fuse_driver.rename('dir', 'dir%20renamed')
        readdir_result = self.fuse_driver.readdir('', None)
        self.assertCountEqual(['.', '..', 'file%20renamed.txt', 'dir%20renamed'], readdir_result)

        self.fuse_driver.write('file%20renamed.txt', b'changed content', 0, None)
        self.fuse_driver.flush('file%20renamed.txt')
        readdir_result = self.fuse_driver.readdir('', None)
        self.assertCountEqual(['.', '..', 'file%20renamed.txt', 'dir%20renamed'], readdir_result)

        self.fuse_driver.create('file renamed.txt', None)
        self.fuse_driver.write('file renamed.txt', b'different content', 0, None)
        self.fuse_driver.flush('file renamed.txt')
        readdir_result = self.fuse_driver.readdir('', None)
        self.assertCountEqual(['.', '..', 'file%20renamed.txt', 'file renamed.txt', 'dir%20renamed'], readdir_result)

        self.fuse_driver.unlink("file%20renamed.txt")
        readdir_result = self.fuse_driver.readdir('', None)
        self.assertCountEqual(['.', '..', 'file renamed.txt', 'dir%20renamed'], readdir_result)

    def test_rmdir(self):
        self.azure_fs.create_directory(self.STORAGE_ACCOUNT_SHARE, 'direxists')
        self.fuse_driver.rmdir('direxists')
        listing = self.azure_fs.list_directories_and_files(self.STORAGE_ACCOUNT_SHARE, '')
        self.assertTrue('direxists' not in [i.name for i in listing.items])

        #with self.assertRaisesRegex(Exception, '\[Errno 2\] No such file or directory'):
        #    self.fuse_driver.rmdir('notfound')
        #with self.assertRaisesRegex(Exception, '\[Errno 13\] Permission denied'):
        #    self.fuse_driver.rmdir('permissionserror1')
        #with self.assertRaisesRegex(Exception, '\[Errno 13\] Permission denied'):
        #    self.fuse_driver.rmdir('permissionserror2')

    def test_unlink(self):
        self.azure_fs.create_file_from_bytes(self.STORAGE_ACCOUNT_SHARE, '', 'file.txt', b'test file content')

        # test delete returns 200 (Okay)
        self.fuse_driver.unlink('file.txt')
        
        # test delete returns 404 (File Not Found)
        with self.assertRaisesRegex(Exception, '\[Errno 2\] No such file or directory'):
            self.fuse_driver.unlink('notfound.txt')

    def test_write(self):
        self.azure_fs.create_file_from_bytes(
            self.STORAGE_ACCOUNT_SHARE, '', 'file.txt', b'best file content')
        fd = self.fuse_driver.open('file.txt', 'w')
        # verify writing 0 length
        self.fuse_driver.write('file.txt', b'', 0, fd)
        self.assertEqual(
            self.azure_fs.get_file_to_bytes(self.STORAGE_ACCOUNT_SHARE, '', 'file.txt').content, 
            b'best file content')
            
        ## verify writing a bit
        self.fuse_driver.write('file.txt', b'v', 0, fd)
        self.fuse_driver.flush('file.txt')
        self.assertEqual(
            self.azure_fs.get_file_to_bytes(self.STORAGE_ACCOUNT_SHARE, '', 'file.txt').content, 
            b'vest file content')
            
        # verify writing the buffer
        self.fuse_driver.write('file.txt', b'a' * 17, 0, fd)
        self.fuse_driver.flush('file.txt')
        self.assertEqual(
            self.azure_fs.get_file_to_bytes(self.STORAGE_ACCOUNT_SHARE, '', 'file.txt').content, 
            b'aaaaaaaaaaaaaaaaa')
        
        # verify writing exceeding the buffer
        self.fuse_driver.write('file.txt', b'a' * 18, 0, fd)
        self.fuse_driver.flush('file.txt')
        self.assertEqual(
            self.azure_fs.get_file_to_bytes(self.STORAGE_ACCOUNT_SHARE, '', 'file.txt').content, 
            b'aaaaaaaaaaaaaaaaaa')
        ## TODO: AssertionError occurred Message=b'aaaaaaaaaaaaaaaaa\x00' != b'aaaaaaaaaaaaaaaaaa'

        # verify writing with negative offset
        with self.assertRaisesRegex(Exception, '\[Errno 22\] Invalid argument'):
            self.fuse_driver.write('file.txt', b'b', -1, fd)
        self.assertEqual(
            self.azure_fs.get_file_to_bytes(self.STORAGE_ACCOUNT_SHARE, '', 'file.txt').content, 
            b'aaaaaaaaaaaaaaaaaa')

        # verify writing to a offset beyond the file
        #with self.assertRaisesRegex(Exception, '\[Errno 22\] Invalid argument'):
        #    self.fuse_driver.write('file.txt', b'b', 19, fd)
        #self.assertEqual(
        #    self.azure_fs.get_file_to_bytes(self.STORAGE_ACCOUNT_SHARE, '', 'file.txt').content, 
        #    b'aaaaaaaaaaaaaaaaaa')

        #with self.assertRaisesRegex(Exception, '\[Errno 22\] Invalid argument'):
        #    self.fuse_driver.write('file.txt', b'c', 21, fd)
        #self.assertEqual(
        #    self.azure_fs.get_file_to_bytes(self.STORAGE_ACCOUNT_SHARE, '', 'file.txt').content, 
        #    b'aaaaaaaaaaaaaaaaaa')

        # verify offset equal to file length
        self.fuse_driver.write('file.txt', b'b', 18, fd)
        self.fuse_driver.flush('file.txt')
        self.assertEqual(
            self.azure_fs.get_file_to_bytes(self.STORAGE_ACCOUNT_SHARE, '', 'file.txt').content, 
            b'aaaaaaaaaaaaaaaaaab')

        # TODO: verify fails if file handle isn't open for write.  (RESPECT
        # ATTRIBUTES OF OPEN, CURRENTLY WE DON'T
    
    # For this test, set "quota" to be the size of the quota you've created.
    def test_quota(self):
        quota = 1250000000

        delta = int(quota / 5) # an arbitrary amount to go under and then over the quota threshold to test it.
        size = quota - delta
        contents = b'a' * size

        self.azure_fs.create_file_from_bytes(
            self.STORAGE_ACCOUNT_SHARE, '', 'file.txt', b'best file content')
        fd = self.fuse_driver.open('file.txt', 'w')
        self.fuse_driver.write('file.txt', b'a', size - 1, fd)
        self.fuse_driver.flush('file.txt')

        self.assertEqual(
            len(self.azure_fs.get_file_to_bytes(self.STORAGE_ACCOUNT_SHARE, '', 'file.txt').content), 
            size)

        self.fuse_driver.write('file.txt', b'b', size + delta * 2, fd)
        time.sleep(1)
        # We expect the second write to fail visibly once the first async write has exceeded quota and failed silently.
        with self.assertRaisesRegex(Exception, '\[Errno 28\] No space left on device'):
            self.fuse_driver.write('file.txt', b'b', size + delta * 2, fd)

        self.assertEqual(
            len(self.azure_fs.get_file_to_bytes(self.STORAGE_ACCOUNT_SHARE, '', 'file.txt').content), 
            size)

    def test_write_getattr_read(self):
        # Created after https://github.com/crwilcox/AzureFilesFUSE/issues/10
        self.fuse_driver.create('file.txt', None)
        write_length = self.fuse_driver.write('file.txt', b'hello\nworld\n', 0, None)
        self.assertEqual(write_length, 12, "Write should have been 12 bytes")
        attrs = self.fuse_driver.getattr('file.txt')
        self.assertEqual(attrs['st_size'], write_length, "Size of GetAttr not matching size of write")
        content = self.fuse_driver.read('file.txt', 5, 0, None)
        self.assertEqual(b'hello', content)

    def test_flush(self):
        # TODO: test internal flush behavior
        pass

    def test_truncate(self):
        # mock write, flush, release
        # TODO: should be local only.  incomplete tests.
        # verify that we strip content (try to read past and look about).
        # verify if we try to truncate non-existent, we err correctly.
        # verify we can't negative truncate.
        self.azure_fs.create_file_from_bytes(
            self.STORAGE_ACCOUNT_SHARE, '', 'file.txt', b'test file content')

        fd = self.fuse_driver.open('file.txt', 'w')

        # test truncating exactly
        self.fuse_driver.truncate('file.txt', 17, fd)
        content = self.azure_fs.get_file_to_bytes(self.STORAGE_ACCOUNT_SHARE, '', 'file.txt').content
        self.assertEqual(content, b'test file content')

        # test truncating over
        self.fuse_driver.truncate('file.txt', 20, fd)
        content = self.azure_fs.get_file_to_bytes(self.STORAGE_ACCOUNT_SHARE, '', 'file.txt').content
        self.assertEqual(content, b'test file content\0\0\0')

        # test truncating smaller
        self.fuse_driver.truncate('file.txt', 9, fd)
        content = self.azure_fs.get_file_to_bytes(self.STORAGE_ACCOUNT_SHARE, '', 'file.txt').content
        self.assertEqual(content, b'test file')

        # test truncating negatively
        with self.assertRaisesRegex(Exception, '\[Errno 22\] Invalid argument'):
            self.fuse_driver.truncate('file.txt', -1, fd)

    def test_release(self):
        self.azure_fs.create_file_from_bytes(
            self.STORAGE_ACCOUNT_SHARE, '', 'file.txt', b'test file content')

        # try to release a non existent descriptor
        self.fuse_driver.release('false.txt', 1)
        cache_entry = self.fuse_driver.file_cache['false.txt']
        self.assertEqual(cache_entry.max_size, 0)

        # read and release file
        self.fuse_driver.read('file.txt', 17, 0, 0)
        self.fuse_driver.release('file.txt', None)
        cache_entry = self.fuse_driver.file_cache['file.txt']
        self.assertEqual(cache_entry.max_size, 0)

    def test_strip_question_from_sas(self):
        q_mark_sas = "?se=2017-07-16T20%3A42%3A33Z&sp=rwdl&sv=2016-05-31&sr=s&sig=C/N0tRE%AlLYaKeyD"
        self.fuse_driver = azfilesfuse.AzureFiles(
            self.STORAGE_ACCOUNT_NAME, self.STORAGE_ACCOUNT_SHARE, q_mark_sas)
        self.assertEqual(self.fuse_driver._sas_token, q_mark_sas[1:], "question mark not stripped")

    #endregion Tests

if __name__ == '__main__':
    unittest.main()

