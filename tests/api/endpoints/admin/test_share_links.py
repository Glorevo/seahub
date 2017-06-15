# -*- coding: utf-8 -*-
import json

from tests.common.utils import randstring
from django.core.urlresolvers import reverse
from seahub.test_utils import BaseTestCase
from seahub.share.models import FileShare

try:
    from seahub.settings import LOCAL_PRO_DEV_ENV
except ImportError:
    LOCAL_PRO_DEV_ENV = False

class ShareLinksTest(BaseTestCase):

    def setUp(self):
        self.repo_id = self.repo.id
        self.file_path= self.file
        self.folder_path= self.folder

    def tearDown(self):
        self.remove_repo()

    def _add_file_share_link(self, password=None):
        fs = FileShare.objects.create_file_link(self.user.username,
            self.repo.id, self.file, password, None)

        return fs.token

    def _add_dir_share_link(self, password=None):
        fs = FileShare.objects.create_dir_link(self.user.username,
            self.repo.id, self.folder, password, None)

        return fs.token

    def _remove_share_link(self, token):
        link = FileShare.objects.get(token=token)
        link.delete()

    def test_get_file_share_link_info_by_token(self):
        self.login_as(self.admin)
        token = self._add_file_share_link()

        url = reverse('api-v2.1-admin-share-link', args=[token])
        resp = self.client.get(url)
        self.assertEqual(200, resp.status_code)

        json_resp = json.loads(resp.content)

        assert json_resp['token'] == token
        assert json_resp['is_dir'] == False

        self._remove_share_link(token)

    def test_get_dir_share_link_info_by_token(self):
        self.login_as(self.admin)
        token = self._add_dir_share_link()

        url = reverse('api-v2.1-admin-share-link', args=[token])
        resp = self.client.get(url)
        self.assertEqual(200, resp.status_code)

        json_resp = json.loads(resp.content)

        assert json_resp['token'] == token
        assert json_resp['is_dir'] == True

        self._remove_share_link(token)

    def test_get_share_link_info_with_invalid_permission(self):
        self.login_as(self.user)
        token = self._add_dir_share_link()

        url = reverse('api-v2.1-admin-share-link', args=[token])
        resp = self.client.get(url)
        resp = self.client.get(url)
        self.assertEqual(403, resp.status_code)

        self._remove_share_link(token)

    def test_password_check(self):
        self.login_as(self.admin)

        #### create file share link ####
        password = randstring(10)
        token = self._add_file_share_link(password)
        url = reverse('api-v2.1-admin-share-link', args=[token])

        # check password for file share link
        resp = self.client.post(url, {'password': password})
        self.assertEqual(200, resp.status_code)

        # get file share link info
        resp = self.client.get(url)
        self.assertEqual(200, resp.status_code)
        json_resp = json.loads(resp.content)
        assert json_resp['token'] == token
        assert json_resp['is_dir'] == False

        # remove file share link
        self._remove_share_link(token)

        #### create dir share link ####
        password = randstring(10)
        token = self._add_dir_share_link(password)
        url = reverse('api-v2.1-admin-share-link', args=[token])

        # check password for dir share link
        resp = self.client.post(url, {'password': password})
        self.assertEqual(200, resp.status_code)

        # get dir share link info
        resp = self.client.get(url)
        self.assertEqual(200, resp.status_code)
        json_resp = json.loads(resp.content)
        assert json_resp['token'] == token
        assert json_resp['is_dir'] == True

        # remove dir share link
        self._remove_share_link(token)

    def test_password_check_with_invalid_permission(self):
        self.login_as(self.user)

        #### create file share link ####
        password = randstring(10)
        token = self._add_file_share_link(password)
        url = reverse('api-v2.1-admin-share-link', args=[token])

        # check password for file share link
        resp = self.client.post(url, {'password': password})
        self.assertEqual(403, resp.status_code)

        self._remove_share_link(token)

    def test_invalid_password_check(self):
        self.login_as(self.user)

        #### create file share link ####
        password = randstring(10)
        token = self._add_file_share_link(password)
        url = reverse('api-v2.1-admin-share-link', args=[token])

        # check password for file share link
        resp = self.client.post(url, {'password': 'invalid_password'})
        self.assertEqual(403, resp.status_code)

        self._remove_share_link(token)
