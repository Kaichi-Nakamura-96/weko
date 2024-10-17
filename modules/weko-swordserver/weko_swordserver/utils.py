# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 National Institute of Informatics.
#
# WEKO-SWORDServer is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Module of weko-swordserver."""

import os
import time
import bagit
import zipfile
import hashlib
import base64
import tempfile

from datetime import datetime, timezone

from flask import current_app, request
from invenio_oauth2server.provider import get_token
from weko_admin.models import AdminSettings
from weko_search_ui.utils import (
    check_tsv_import_items,
    check_xml_import_items
    )
from weko_workflow.models import ActionStatusPolicy, WorkFlow

from .errors import WekoSwordserverException, ErrorType
from .models import SwordClient, SwordItemTypeMapping


def check_import_file_format(file, packaging):
    """Check inport file format.

    Args:
        file (str): Import file
        packaging (str): Packaging in request header

    Raises:
        WekoSwordserverException: _description_

    Returns:
        str: Import file format
    """
    if packaging == 'SWORDBagIt':
        file_format = 'SWORD'
    elif packaging == 'SimpleZip':
        file_list = get_file_list_of_zip(file)
        if 'ro-crate-metadata.json' in file_list:
            file_format = 'ROCRATE'
        else:
            file_format = 'OTHERS'
    else:
        raise WekoSwordserverException(
            "No Package Included.",ErrorType.BadRequest
            )

    return file_format


def is_valid_body_hash(digest, body):
    """Validate body hash.

    Validate body hash by comparing to digest in request headers.
    When body hash is valid : return True.
    Else : return False.

    Args:
        digest (): Digest in request headers.
        body (): Request body.

    Returns:
        bool: Check result.
    """
    body_hash = hashlib.sha256(body).digest()
    body_hash_base64 = base64.b64encode(body_hash).decode()

    result = False

    if (digest.startwith('SHA-256=')
        and digest.split('SHA-256=') == body_hash_base64):
        result = True

    return result


def get_mapping_by_token(access_token):
    """Get mapping by token.

    Get mapping for RO-Crate matadata by access token.

    Args:
        access_token (str): Access token.

    Returns:
        SwordItemTypeMapping: Mapping for RO-Crate matadata.
    """
    token = get_token(access_token=access_token)
    if token is None:
        current_app.logger.error(f"Token not found.")
        raise WekoSwordserverException(
            "Token not found.", errorType=ErrorType.ServerError
        )

    client_id = token.client_id
    sword_client = SwordClient.get_client_by_id(client_id)

    mapping_id = sword_client.mapping_id if sword_client is not None else None
    mapping = SwordItemTypeMapping.get_mapping_by_id(mapping_id)

    return mapping


def check_bagit_import_items(file, header, file_format):
    check_result = {}
    register_format = ""

    # TODO: extension zip in tmporary directory

    # TODO: check request header
    # check_digest(header)

    # TODO: check bagit files
    file_list = get_file_list_of_zip(file)

    # Check if all required files are contained
    if file_format == 'ROCRATE':
        all_file_contained = all(check_rocrate_required_files(file_list))
    elif file_format == 'SWORD':
        all_file_contained = all(check_swordbagit_required_files(file_list))

    if not all_file_contained:
        raise ValueError('Metadata JSON File\
                         Or "manifest-sha-256.txt" Is Lacking')

    try:
        bag = bagit.Bag(data_path)
        if bag.is_valid():
            print("BagItアーカイブは有効です。")
            is_valid_bagit = True
        else:
            print("BagItアーカイブは無効です。")
            is_valid_bagit = False
    except bagit.BagValidationError as e:
        print(f"BagItアーカイブの検証中にエラーが発生しました: {e}")
        is_valid_bagit = False

    if not is_valid_bagit:
        raise ValueError('Invalid BagIt Format')

    sword_mapping = get_mapping_by_token(header["access_token"])
    if sword_mapping is None:
        current_app.logger.error(f"Mapping not found by your token.")
        raise WekoSwordserverException(
            "Mapping not found by your token.",
            errorType=ErrorType.MappingNotFound
        )

    mapping = sword_mapping.mapping
    register_format = sword_mapping.registration_type

    # TODO: validate mapping

    # TODO: make check_result

    return check_result, register_format


def check_others_import_items(file, is_change_identifier: bool = False):
    settings = AdminSettings.get("sword_api_setting", dict_to_object=False)
    default_format = settings.get("default_format")
    data_format = settings.get("data_format")
    if default_format == "TSV":
        check_tsv_result = check_tsv_import_items(file, is_change_identifier)
        if check_tsv_result.get("error"):
            # try xml
            time.sleep(1)
            workflow_id = int(data_format.get("XML", {}).get("workflow", "-1"))
            workflow = WorkFlow.query.get(workflow_id)
            if not workflow or workflow.is_deleted:
                raise WekoSwordserverException("Workflow is not configured for importing xml.", ErrorType.ServerError)
            item_type_id = workflow.itemtype_id
            check_xml_result = check_xml_import_items(
                file, item_type_id, is_gakuninrdm=False
            )
            if check_xml_result.get("error"):
                return check_tsv_result, None
            else:
                return check_xml_result, "Workflow" # data_format['XML']['register_format']
        else:
            return check_tsv_result, "Direct" # data_format['TSV']['register_format']
    elif default_format == "XML":
        workflow_id = int(data_format.get("XML", {}).get("workflow", "-1"))
        workflow = WorkFlow.query.get(workflow_id)
        if not workflow or workflow.is_deleted:
            raise WekoSwordserverException("Workflow is not configured for importing xml.", ErrorType.ServerError)
        item_type_id = workflow.itemtype_id
        check_xml_result = check_xml_import_items(
            file, item_type_id, is_gakuninrdm=False
        )
        if check_xml_result.get("error"):
            # try tsv
            time.sleep(1)
            check_tsv_result = check_tsv_import_items(file, is_change_identifier)
            if check_tsv_result.get("error"):
                return check_xml_result, None
            else:
                return check_tsv_result, "Direct" # data_format['TSV']['register_format']
        else:
            return check_xml_result, "Workflow" # data_format['XML']['register_format']

    return {}, None


# 中村追加処理-2
def check_rocrate_required_files(file_list):
    """Check RO-Crate required files.

    Args:
        file_list (list): FIle list of zip.

    Returns:
        list: List of results.
    """
    list_required_files = [
        'manifest-sha-256.txt',
        'ro-crate-metadata.json'
    ]

    return [required_file in file_list
            for required_file in list_required_files]


# 中村追加処理-3
def check_swordbagit_required_files(file_list):
    """Check SWORDBagIt required files.

    Args:
        file_list (list): FIle list of zip.

    Returns:
        list: List of results.
    """
    list_required_files = [
        'manifest-sha-256.txt',
        'metadata/sword.json'
    ]

    return [required_file in file_list
            for required_file in list_required_files]


# 中村追加処理-4
def get_file_list_of_zip(file, is_gakuninrdm=False):
    """Get file list of zip.

    Args:
        file (_type_): Zip file.
        is_gakuninrdm (bool, optional): _description_. Defaults to False.

    Returns:
        list: File list
    """
    if not is_gakuninrdm:
        tmp_prefix = current_app.config["WEKO_SEARCH_UI_IMPORT_TMP_PREFIX"]
    else:
        tmp_prefix = "deposit_activity_"
    tmp_dirname = (tmp_prefix
                   + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"))
    data_path = os.path.join(tempfile.gettempdir(), tmp_dirname)
    result = {"data_path": data_path}

    # Create temp dir for import data
    os.mkdir(data_path)

    with zipfile.ZipFile(file, 'r') as zip_ref:
        zip_ref.extractall(data_path)
        file_list =  zip_ref.namelist()

    return file_list


# 中村追加処理-6
def calculate_sha256(file_path):
    """Calculate SHA-256 of a file.

    Args:
        file_path (str): target file path

    Returns:
        str: result
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


# 中村追加処理-7
def check_manifest_sha_256(manifest_path):
    """Validate manifest/tagmanifest-sha-256.txt.

    Validate all SHA-256 of each file in manifest/tagmanifest-sha-256.txt file.

    When all SHA-256 correct : return True.
    Else : return False.

    Args:
        manifest_path (str): manifest/tagmanifest-sha-256.txt file path

    Returns:
        bool: result
    """
    with open(manifest_path, "r") as manifest_file:
        for line in manifest_file:
            hash_value, file_path = line.strip().split(maxsplit=1)
            calculated_hash = calculate_sha256(file_path)
            if hash_value == calculated_hash:
                # print(f"{file_path}: OK")
                return True
            else:
                # print(f"{file_path}: MISMATCH (expected {hash_value}, got {calculated_hash})")
                return False

