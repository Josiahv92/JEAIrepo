"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_2' block
    filter_2(container=container)

    return

@phantom.playbook_block()
def source_ip_formatting(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("source_ip_formatting() called")

    template = """%%\nSource Address(es): {0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_2:condition_1:artifact:*.cef.sourceAddress"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="source_ip_formatting", drop_none=True)

    add_soar_note_3(container=container)

    return


@phantom.playbook_block()
def add_soar_note_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_soar_note_3() called")

    source_ip_formatting = phantom.get_format_data(name="source_ip_formatting")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=source_ip_formatting, note_format="markdown", note_type="general", title="IP Findings")

    source_ip_investigation(container=container)

    return


@phantom.playbook_block()
def source_dns_formatting(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("source_dns_formatting() called")

    template = """%%\nSource DNS Domain(s): {0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_3:condition_1:artifact:*.cef.sourceDnsDomain"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="source_dns_formatting", drop_none=True)

    add_soar_note_1(container=container)

    return


@phantom.playbook_block()
def add_soar_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_soar_note_1() called")

    source_dns_formatting = phantom.get_format_data(name="source_dns_formatting")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=source_dns_formatting, note_format="markdown", note_type="general", title="Source DNS Findings")

    source_dns_investigation(container=container)

    return


@phantom.playbook_block()
def url_formatting(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("url_formatting() called")

    template = """%%\nRequest URL(s): {0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_2:condition_3:artifact:*.cef.requestURL"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="url_formatting", drop_none=True)

    add_soar_note_2(container=container)

    return


@phantom.playbook_block()
def sha1_hash_formatting(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("sha1_hash_formatting() called")

    template = """%%\nSHA1 Hash(es): {0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_4:condition_1:artifact:*.cef.fileHashSha1"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="sha1_hash_formatting", drop_none=True)

    add_soar_note(container=container)

    return


@phantom.playbook_block()
def add_soar_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_soar_note_2() called")

    url_formatting = phantom.get_format_data(name="url_formatting")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=url_formatting, note_format="markdown", note_type="general", title="URL Findings")

    url_investigation(container=container)

    return


@phantom.playbook_block()
def add_soar_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_soar_note() called")

    sha1_hash_formatting = phantom.get_format_data(name="sha1_hash_formatting")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=sha1_hash_formatting, note_format="markdown", note_type="general", title="SHA1 Hash Findings")

    sha1_investigation(container=container)

    return


@phantom.playbook_block()
def source_ip_investigation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("source_ip_investigation() called")

    filtered_artifact_0_data_filter_2 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_1:artifact:*.cef.sourceAddress"])

    filtered_artifact_0__cef_sourceaddress = [item[0] for item in filtered_artifact_0_data_filter_2]

    ipaddress_combined_value = phantom.concatenate(filtered_artifact_0__cef_sourceaddress, dedup=True)

    inputs = {
        "ipaddress": ipaddress_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/GMS - IP Investigation - Child Playbook", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/GMS - IP Investigation - Child Playbook", container=container, inputs=inputs)

    source_ip_containment(container=container)

    return


@phantom.playbook_block()
def url_investigation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("url_investigation() called")

    filtered_artifact_0_data_filter_2 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_3:artifact:*.cef.requestURL"])

    filtered_artifact_0__cef_requesturl = [item[0] for item in filtered_artifact_0_data_filter_2]

    url_combined_value = phantom.concatenate(filtered_artifact_0__cef_requesturl, dedup=True)

    inputs = {
        "url": url_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/GMS - URL Investigation - Child Playbook", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/GMS - URL Investigation - Child Playbook", container=container, inputs=inputs)

    url_containment(container=container)

    return


@phantom.playbook_block()
def sha1_investigation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("sha1_investigation() called")

    filtered_artifact_0_data_filter_4 = phantom.collect2(container=container, datapath=["filtered-data:filter_4:condition_1:artifact:*.cef.fileHashSha1"])

    filtered_artifact_0__cef_filehashsha1 = [item[0] for item in filtered_artifact_0_data_filter_4]

    file_hash_combined_value = phantom.concatenate(filtered_artifact_0__cef_filehashsha1, dedup=True)

    inputs = {
        "file_hash": file_hash_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/GMS - File Hash Investigation - Child Playbook", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/GMS - File Hash Investigation - Child Playbook", container=container, inputs=inputs)

    sha1_containment(container=container)

    return


@phantom.playbook_block()
def source_ip_containment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("source_ip_containment() called")

    filtered_artifact_0_data_filter_2 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_1:artifact:*.cef.sourceAddress"])

    filtered_artifact_0__cef_sourceaddress = [item[0] for item in filtered_artifact_0_data_filter_2]

    ipaddress_combined_value = phantom.concatenate(filtered_artifact_0__cef_sourceaddress, dedup=True)

    inputs = {
        "ipaddress": ipaddress_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/GMS - IP Containment - Child Playbook", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/GMS - IP Containment - Child Playbook", container=container, inputs=inputs)

    return


@phantom.playbook_block()
def source_dns_investigation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("source_dns_investigation() called")

    filtered_artifact_0_data_filter_3 = phantom.collect2(container=container, datapath=["filtered-data:filter_3:condition_1:artifact:*.cef.sourceDnsDomain"])

    filtered_artifact_0__cef_sourcednsdomain = [item[0] for item in filtered_artifact_0_data_filter_3]

    domain_combined_value = phantom.concatenate(filtered_artifact_0__cef_sourcednsdomain, dedup=True)

    inputs = {
        "domain": domain_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/GMS - Domain Investigation - Child Playbook", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/GMS - Domain Investigation - Child Playbook", container=container, inputs=inputs)

    source_dns_containment(container=container)

    return


@phantom.playbook_block()
def url_containment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("url_containment() called")

    filtered_artifact_0_data_filter_2 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_3:artifact:*.cef.requestURL"])

    filtered_artifact_0__cef_requesturl = [item[0] for item in filtered_artifact_0_data_filter_2]

    domain_combined_value = phantom.concatenate(filtered_artifact_0__cef_requesturl, dedup=True)

    inputs = {
        "domain": domain_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/GMS - Domain Containment - Child Playbook", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/GMS - Domain Containment - Child Playbook", container=container, inputs=inputs)

    return


@phantom.playbook_block()
def source_dns_containment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("source_dns_containment() called")

    filtered_artifact_0_data_filter_3 = phantom.collect2(container=container, datapath=["filtered-data:filter_3:condition_2:artifact:*.cef.sourceDnsDomain"])

    filtered_artifact_0__cef_sourcednsdomain = [item[0] for item in filtered_artifact_0_data_filter_3]

    domain_combined_value = phantom.concatenate(filtered_artifact_0__cef_sourcednsdomain, dedup=True)

    inputs = {
        "domain": domain_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/GMS - Domain Containment - Child Playbook", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/GMS - Domain Containment - Child Playbook", container=container, inputs=inputs)

    return


@phantom.playbook_block()
def sha1_containment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("sha1_containment() called")

    filtered_artifact_0_data_filter_4 = phantom.collect2(container=container, datapath=["filtered-data:filter_4:condition_1:artifact:*.cef.fileHashSha1"])

    filtered_artifact_0__cef_filehashsha1 = [item[0] for item in filtered_artifact_0_data_filter_4]

    file_hash_combined_value = phantom.concatenate(filtered_artifact_0__cef_filehashsha1, dedup=True)

    inputs = {
        "file_hash": file_hash_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/GMS - File Hash Containment - Child Playbook", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/GMS - File Hash Containment - Child Playbook", container=container, inputs=inputs)

    return


@phantom.playbook_block()
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_2() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress", "!=", ""]
        ],
        conditions_dps=[
            ["artifact:*.cef.sourceAddress", "!=", ""]
        ],
        name="filter_2:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        source_ip_formatting(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAddress", "!=", ""]
        ],
        conditions_dps=[
            ["artifact:*.cef.destinationAddress", "!=", ""]
        ],
        name="filter_2:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        destination_ip_formatting(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids and results for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""]
        ],
        conditions_dps=[
            ["artifact:*.cef.requestURL", "!=", ""]
        ],
        name="filter_2:condition_3",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        url_formatting(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    # collect filtered artifact ids and results for 'if' condition 4
    matched_artifacts_4, matched_results_4 = phantom.condition(
        container=container,
        logical_operator="or",
        conditions=[
            ["artifact:*.cef.sourceDnsDomain", "!=", ""],
            ["artifact:*.cef.destinationDnsDomain", "!=", ""]
        ],
        conditions_dps=[
            ["artifact:*.cef.sourceDnsDomain", "!=", ""],
            ["artifact:*.cef.destinationDnsDomain", "!=", ""]
        ],
        name="filter_2:condition_4",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_4 or matched_results_4:
        filter_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_4, filtered_results=matched_results_4)

    # collect filtered artifact ids and results for 'if' condition 5
    matched_artifacts_5, matched_results_5 = phantom.condition(
        container=container,
        logical_operator="or",
        conditions=[
            ["artifact:*.cef.fileHashSha1", "!=", ""],
            ["artifact:*.cef.fileHashSha256", "!=", ""],
            ["artifact:*.cef.fileHashMd5", "!=", ""],
            ["artifact:*.cef.fileHash", "!=", ""]
        ],
        conditions_dps=[
            ["artifact:*.cef.fileHashSha1", "!=", ""],
            ["artifact:*.cef.fileHashSha256", "!=", ""],
            ["artifact:*.cef.fileHashMd5", "!=", ""],
            ["artifact:*.cef.fileHash", "!=", ""]
        ],
        name="filter_2:condition_5",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_5 or matched_results_5:
        filter_4(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_5, filtered_results=matched_results_5)

    return


@phantom.playbook_block()
def destination_ip_formatting(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("destination_ip_formatting() called")

    template = """%%\nDestination Address(es): {0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_2:condition_2:artifact:*.cef.destinationAddress"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="destination_ip_formatting")

    add_soar_note_4(container=container)

    return


@phantom.playbook_block()
def add_soar_note_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_soar_note_4() called")

    destination_ip_formatting = phantom.get_format_data(name="destination_ip_formatting")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=destination_ip_formatting, note_format="markdown", note_type="general", title="IP Findings")

    destination_ip_investigation(container=container)

    return


@phantom.playbook_block()
def destination_ip_investigation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("destination_ip_investigation() called")

    filtered_artifact_0_data_filter_2 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_2:artifact:*.cef.destinationAddress"])

    filtered_artifact_0__cef_destinationaddress = [item[0] for item in filtered_artifact_0_data_filter_2]

    ipaddress_combined_value = phantom.concatenate(filtered_artifact_0__cef_destinationaddress, dedup=True)

    inputs = {
        "ipaddress": ipaddress_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/GMS - IP Investigation - Child Playbook", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/GMS - IP Investigation - Child Playbook", container=container, inputs=inputs)

    destination_ip_containment(container=container)

    return


@phantom.playbook_block()
def destination_ip_containment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("destination_ip_containment() called")

    filtered_artifact_0_data_filter_2 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_2:artifact:*.cef.destinationAddress"])

    filtered_artifact_0__cef_destinationaddress = [item[0] for item in filtered_artifact_0_data_filter_2]

    ipaddress_combined_value = phantom.concatenate(filtered_artifact_0__cef_destinationaddress, dedup=True)

    inputs = {
        "ipaddress": ipaddress_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/GMS - IP Containment - Child Playbook", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/GMS - IP Containment - Child Playbook", container=container, inputs=inputs)

    return


@phantom.playbook_block()
def destination_dns_formatting(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("destination_dns_formatting() called")

    template = """%%\nDestination DNS Domain(s): {0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        ""
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="destination_dns_formatting")

    add_soar_note_5(container=container)

    return


@phantom.playbook_block()
def add_soar_note_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_soar_note_5() called")

    destination_dns_formatting = phantom.get_format_data(name="destination_dns_formatting")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=destination_dns_formatting, note_format="markdown", note_type="general", title="Destination DNS Findings")

    destination_dns_investigation(container=container)

    return


@phantom.playbook_block()
def destination_dns_investigation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("destination_dns_investigation() called")

    filtered_artifact_0_data_filter_3 = phantom.collect2(container=container, datapath=["filtered-data:filter_3:condition_2:artifact:*.cef.destinationDnsDomain"])

    filtered_artifact_0__cef_destinationdnsdomain = [item[0] for item in filtered_artifact_0_data_filter_3]

    domain_combined_value = phantom.concatenate(filtered_artifact_0__cef_destinationdnsdomain, dedup=True)

    inputs = {
        "domain": domain_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/GMS - Domain Investigation - Child Playbook", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/GMS - Domain Investigation - Child Playbook", container=container, inputs=inputs)

    destination_dns_containment_1(container=container)

    return


@phantom.playbook_block()
def destination_dns_containment_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("destination_dns_containment_1() called")

    filtered_artifact_0_data_filter_3 = phantom.collect2(container=container, datapath=["filtered-data:filter_3:condition_2:artifact:*.cef.destinationDnsDomain"])

    filtered_artifact_0__cef_destinationdnsdomain = [item[0] for item in filtered_artifact_0_data_filter_3]

    domain_combined_value = phantom.concatenate(filtered_artifact_0__cef_destinationdnsdomain, dedup=True)

    inputs = {
        "domain": domain_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/GMS - Domain Containment - Child Playbook", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/GMS - Domain Containment - Child Playbook", container=container, inputs=inputs)

    return


@phantom.playbook_block()
def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_3() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceDnsDomain", "!=", ""]
        ],
        conditions_dps=[
            ["artifact:*.cef.sourceDnsDomain", "!=", ""]
        ],
        name="filter_3:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        source_dns_formatting(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationDnsDomain", "!=", ""]
        ],
        conditions_dps=[
            ["artifact:*.cef.destinationDnsDomain", "!=", ""]
        ],
        name="filter_3:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        destination_dns_formatting(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def filter_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_4() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHashSha1", "!=", ""]
        ],
        conditions_dps=[
            ["artifact:*.cef.fileHashSha1", "!=", ""]
        ],
        name="filter_4:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        sha1_hash_formatting(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHashSha256", "!=", ""]
        ],
        conditions_dps=[
            ["artifact:*.cef.fileHashSha256", "!=", ""]
        ],
        name="filter_4:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        sha256_hash_formatting(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids and results for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHashMd5", "!=", ""]
        ],
        conditions_dps=[
            ["artifact:*.cef.fileHashMd5", "!=", ""]
        ],
        name="filter_4:condition_3",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        md5_hash_formatting(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    # collect filtered artifact ids and results for 'if' condition 4
    matched_artifacts_4, matched_results_4 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHash", "!=", ""]
        ],
        conditions_dps=[
            ["artifact:*.cef.fileHash", "!=", ""]
        ],
        name="filter_4:condition_4",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_4 or matched_results_4:
        file_hash_formatting(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_4, filtered_results=matched_results_4)

    return


@phantom.playbook_block()
def sha256_hash_formatting(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("sha256_hash_formatting() called")

    template = """%%\nSHA1 Hash(es): {0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_4:condition_2:artifact:*.cef.fileHashSha256"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="sha256_hash_formatting")

    add_soar_note_6(container=container)

    return


@phantom.playbook_block()
def add_soar_note_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_soar_note_6() called")

    sha256_hash_formatting = phantom.get_format_data(name="sha256_hash_formatting")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=sha256_hash_formatting, note_format="markdown", note_type="general", title="SHA256 Hash Findings")

    sha256_investigation(container=container)

    return


@phantom.playbook_block()
def sha256_investigation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("sha256_investigation() called")

    filtered_artifact_0_data_filter_4 = phantom.collect2(container=container, datapath=["filtered-data:filter_4:condition_2:artifact:*.cef.fileHashSha256"])

    filtered_artifact_0__cef_filehashsha256 = [item[0] for item in filtered_artifact_0_data_filter_4]

    file_hash_combined_value = phantom.concatenate(filtered_artifact_0__cef_filehashsha256, dedup=True)

    inputs = {
        "file_hash": file_hash_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/GMS - File Hash Investigation - Child Playbook", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/GMS - File Hash Investigation - Child Playbook", container=container, inputs=inputs)

    sha256_containment(container=container)

    return


@phantom.playbook_block()
def sha256_containment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("sha256_containment() called")

    filtered_artifact_0_data_filter_4 = phantom.collect2(container=container, datapath=["filtered-data:filter_4:condition_2:artifact:*.cef.fileHashSha256"])

    filtered_artifact_0__cef_filehashsha256 = [item[0] for item in filtered_artifact_0_data_filter_4]

    file_hash_combined_value = phantom.concatenate(filtered_artifact_0__cef_filehashsha256, dedup=True)

    inputs = {
        "file_hash": file_hash_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/GMS - File Hash Containment - Child Playbook", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/GMS - File Hash Containment - Child Playbook", container=container, inputs=inputs)

    return


@phantom.playbook_block()
def md5_hash_formatting(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("md5_hash_formatting() called")

    template = """%%\nMD5 Hash(es): {0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_4:condition_3:artifact:*.cef.fileHashMd5"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="md5_hash_formatting")

    add_soar_note_7(container=container)

    return


@phantom.playbook_block()
def add_soar_note_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_soar_note_7() called")

    md5_hash_formatting = phantom.get_format_data(name="md5_hash_formatting")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=md5_hash_formatting, note_format="markdown", note_type="general", title="MD5 Hash Findings")

    md5_investigation(container=container)

    return


@phantom.playbook_block()
def md5_containment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("md5_containment() called")

    filtered_artifact_0_data_filter_4 = phantom.collect2(container=container, datapath=["filtered-data:filter_4:condition_3:artifact:*.cef.fileHashMd5"])

    filtered_artifact_0__cef_filehashmd5 = [item[0] for item in filtered_artifact_0_data_filter_4]

    file_hash_combined_value = phantom.concatenate(filtered_artifact_0__cef_filehashmd5, dedup=True)

    inputs = {
        "file_hash": file_hash_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/GMS - File Hash Containment - Child Playbook", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/GMS - File Hash Containment - Child Playbook", container=container, inputs=inputs)

    return


@phantom.playbook_block()
def md5_investigation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("md5_investigation() called")

    filtered_artifact_0_data_filter_4 = phantom.collect2(container=container, datapath=["filtered-data:filter_4:condition_3:artifact:*.cef.fileHashMd5"])

    filtered_artifact_0__cef_filehashmd5 = [item[0] for item in filtered_artifact_0_data_filter_4]

    file_hash_combined_value = phantom.concatenate(filtered_artifact_0__cef_filehashmd5, dedup=True)

    inputs = {
        "file_hash": file_hash_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/GMS - File Hash Investigation - Child Playbook", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/GMS - File Hash Investigation - Child Playbook", container=container, inputs=inputs)

    md5_containment(container=container)

    return


@phantom.playbook_block()
def file_hash_formatting(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("file_hash_formatting() called")

    template = """%%\nFile Hash(es): {0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_4:condition_4:artifact:*.cef.fileHash"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="file_hash_formatting")

    add_soar_note_8(container=container)

    return


@phantom.playbook_block()
def add_soar_note_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_soar_note_8() called")

    file_hash_formatting = phantom.get_format_data(name="file_hash_formatting")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=file_hash_formatting, note_format="markdown", note_type="general", title="Default Hash Findings")

    hash_investigation(container=container)

    return


@phantom.playbook_block()
def hash_investigation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("hash_investigation() called")

    filtered_artifact_0_data_filter_4 = phantom.collect2(container=container, datapath=["filtered-data:filter_4:condition_4:artifact:*.cef.fileHash"])

    filtered_artifact_0__cef_filehash = [item[0] for item in filtered_artifact_0_data_filter_4]

    file_hash_combined_value = phantom.concatenate(filtered_artifact_0__cef_filehash, dedup=True)

    inputs = {
        "file_hash": file_hash_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/GMS - File Hash Investigation - Child Playbook", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/GMS - File Hash Investigation - Child Playbook", container=container, inputs=inputs)

    hash_containment(container=container)

    return


@phantom.playbook_block()
def hash_containment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("hash_containment() called")

    filtered_artifact_0_data_filter_4 = phantom.collect2(container=container, datapath=["filtered-data:filter_4:condition_4:artifact:*.cef.fileHash"])

    filtered_artifact_0__cef_filehash = [item[0] for item in filtered_artifact_0_data_filter_4]

    file_hash_combined_value = phantom.concatenate(filtered_artifact_0__cef_filehash, dedup=True)

    inputs = {
        "file_hash": file_hash_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/GMS - File Hash Containment - Child Playbook", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/GMS - File Hash Containment - Child Playbook", container=container, inputs=inputs)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return