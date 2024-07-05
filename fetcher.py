#!/usr/bin/python3.9
# -*- encoding: utf-8 -*-

import boto3
import logging
import traceback
import requests
import os
import re
import json
import time

from requests.auth import HTTPBasicAuth

# Configure logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Environment variables
API_KEYS_SECRET_MANAGER_NAME = os.environ["API_KEYS_SECRET_MANAGER_NAME"]
STREAM_NAME = os.environ["FIREHOSE_STREAM_NAME"]


def retrieve_sensitive_data(secret_manager_name):
    """
    Retrieves sensitive information from AWS secret manager.

    Args:
        secret_manager_name (str): Name of the secret manager.

    Returns:
        dict: Sensitive data retrieved from the secret manager.
    """


def fetch_coordinates_from_google_maps(st_address, zip_code, api_keys):
    """
    Retrieves geo-coordinates from Google Maps API.

    Args:
        st_address (str): street address
        zip_code (int): zip code
        api_keys (dict): API keys for authentication.

    Returns:
        dict: Geo-coordinates.
    """

def get_data_from_socrata_and_send_to_s3(api_keys):
    """
    Retrieves data from Socrata API and sends it to Amazon Kinesis Firehose.

    Args:
        api_keys (dict): API keys for authentication.
    """


def lambda_handler(event, context):
    """
    Lambda function handler.

    Args:
        event: Lambda event input.
        context: Lambda context.

    Returns:
        None
    """
    try:
        # Retrieve Socrata API keys and send data to Firehose
        api_keys = retrieve_sensitive_data(API_KEYS_SECRET_MANAGER_NAME)
        get_data_from_socrata_and_send_to_s3(api_keys)

        logger.info("SF incident data successfully ingested into S3")
    except Exception as error:
        logger.error(traceback.format_exc())