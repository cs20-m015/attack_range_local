
import sys
import os
import time
from time import sleep
import splunklib.client as client
import splunklib.results as results
import requests
from xml.etree import ElementTree


def export_search(host, s, password, export_mode="raw", out=sys.stdout, username="admin", port=8089):
    """
    Exports events from a search using Splunk REST API to a local file.

    This is faster than performing a search/export from Splunk Python SDK.

    @param host: splunk server address
    @param s: search that matches events
    @param password: Splunk server password
    @param export_mode: default `raw`. `csv`, `xml`, or `json`
    @param out: local file pointer to write the results
    @param username: Splunk server username
    @param port: Splunk server port
    """
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    r = requests.post("https://%s:%d/servicesNS/admin/search/search/jobs/export" % (host, port),
                      auth=(username, password),
                      data={'output_mode': export_mode,
                            'search': s,
                            'max_count': 1000000},
                      verify=False)
    out.write(r.text.encode('utf-8'))

def test_baseline_search(splunk_host, splunk_password, search, pass_condition, baseline_name, baseline_file, earliest_time, latest_time, log, splunk_rest_port=8089):
    try:
        service = client.connect(
            host=splunk_host,
            port=splunk_rest_port,
            username='admin',
            password=splunk_password
        )
    except Exception as e:
        log.error("Unable to connect to Splunk instance: " + str(e))
        return {}

    if search.startswith('|'):
        search = search
    else:
        search = 'search ' + search

    kwargs = {"exec_mode": "blocking",
              "dispatch.earliest_time": earliest_time,
              "dispatch.latest_time": latest_time}

    splunk_search = search + ' ' + pass_condition
    test_results = dict()
    test_results['baseline_name'] = baseline_name
    test_results['baseline_file'] = baseline_file
    test_results["splunk_search"] = splunk_search

    try:
        job = service.jobs.create(splunk_search, **kwargs)
    except Exception as e:
        log.error("Unable to execute baseline: " + str(e))
        test_results['error'] = True
        test_results['messages'] = {"error": [str(e)]}
        return test_results

    try:
        test_results['diskUsage'] = job['diskUsage']
        test_results['runDuration'] = job['runDuration']
        test_results['scanCount'] = job['scanCount']
        test_results["resultCount"] = job['resultCount']
        test_results["messages"] = job["messages"]

    except Exception as exc:
        log.error(f"Caught an exception during updating test_results in test_baseline_search, exception: {exc}")


    if int(job['resultCount']) != 1:
        log.error("Test failed for baseline: " + baseline_name)
        test_results['error'] = True
        return test_results
    else:
        log.info("Test successful for baseline: " + baseline_name)
        test_results['error'] = False
        return test_results


def test_detection_search(splunk_host, splunk_password, search, pass_condition, detection_name, detection_file, earliest_time, latest_time, log, splunk_rest_port=8089):
    try:
        service = client.connect(
            host=splunk_host,
            port=splunk_rest_port,
            username='admin',
            password=splunk_password
        )
    except Exception as e:
        log.error("Unable to connect to Splunk instance: " + str(e))
        return {}

    if search.startswith('|'):
        search = search
    else:
        search = 'search ' + search

    kwargs = {"exec_mode": "blocking",
              "dispatch.earliest_time": earliest_time,
              "dispatch.latest_time": latest_time}

    splunk_search = search + ' ' + pass_condition
    test_results = dict()
    test_results['detection_name'] = detection_name
    test_results['detection_file'] = detection_file
    test_results["splunk_search"] = splunk_search

    try:
        job = service.jobs.create(splunk_search, **kwargs)
    except Exception as e:
        log.error("Unable to execute detection: " + str(e))
        test_results['error'] = True
        test_results['messages'] = {"error": [str(e)]}
        return test_results

    try:
        test_results['diskUsage'] = job['diskUsage']
        test_results['runDuration'] = job['runDuration']
        test_results['scanCount'] = job['scanCount']
        test_results["resultCount"] = job['resultCount']
        test_results["messages"] = job["messages"]

    except Exception as exc:
        log.error(f"Caught an exception during updating test_results in test_detection_search, exception: {exc}")


    if int(job['resultCount']) != 1:
        test_results['error'] = False
        return test_results
    else:
        log.info("detection found: " + detection_name)
        test_results['error'] = False
        return test_results
