# Copyright (c) 2012-2016 Seafile Ltd.
import os
import logging

from rest_framework import status

from seaserv import ccnet_api, seafile_api
from pysearpc import SearpcError

from seahub.api2.utils import api_error
from seahub.utils.timeutils import datetime_to_isoformat_timestr
from seahub.utils import gen_shared_link

logger = logging.getLogger(__name__)

def api_check_group(func):
    """
    Decorator for check if group valid
    """
    def _decorated(view, request, group_id, *args, **kwargs):
        group_id = int(group_id) # Checked by URL Conf
        try:
            group = ccnet_api.get_group(group_id)
        except SearpcError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        if not group:
            error_msg = 'Group %d not found.' % group_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        return func(view, request, group_id, *args, **kwargs)

    return _decorated

def get_share_link_info(sharelink):
    data = {}
    token = sharelink.token

    repo_id = sharelink.repo_id
    try:
        repo = seafile_api.get_repo(repo_id)
    except Exception as e:
        logger.error(e)
        repo = None

    path = sharelink.path
    if path:
        obj_name = '/' if path == '/' else os.path.basename(path.rstrip('/'))
    else:
        obj_name = ''

    if sharelink.expire_date:
        expire_date = datetime_to_isoformat_timestr(sharelink.expire_date)
    else:
        expire_date = ''

    if sharelink.ctime:
        ctime = datetime_to_isoformat_timestr(sharelink.ctime)
    else:
        ctime = ''

    data['username'] = sharelink.username
    data['repo_id'] = repo_id
    data['repo_name'] = repo.repo_name if repo else ''

    data['path'] = path
    data['obj_name'] = obj_name
    data['is_dir'] = True if sharelink.s_type == 'd' else False

    data['token'] = token
    data['link'] = gen_shared_link(token, sharelink.s_type)
    data['view_cnt'] = sharelink.view_cnt
    data['ctime'] = ctime
    data['expire_date'] = expire_date
    data['is_expired'] = sharelink.is_expired()

    return data
