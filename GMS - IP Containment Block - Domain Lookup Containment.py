"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'abuseipdb_ip_lookup' block
    abuseipdb_ip_lookup(container=container)

    return

@phantom.playbook_block()
def abuseipdb_ip_lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("abuseipdb_ip_lookup() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    playbook_input_ipaddress = phantom.collect2(container=container, datapath=["playbook_input:ipaddress"])

    parameters = []

    # build parameters list for 'abuseipdb_ip_lookup' call
    for playbook_input_ipaddress_item in playbook_input_ipaddress:
        if playbook_input_ipaddress_item[0] is not None:
            parameters.append({
                "ip": playbook_input_ipaddress_item[0],
                "days": 10,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("lookup ip", parameters=parameters, name="abuseipdb_ip_lookup", assets=["abuseipdb"], callback=filter_1)

    return


@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["abuseipdb_ip_lookup:action_result.data.*.data.domain", "!=", ""]
        ],
        conditions_dps=[
            ["abuseipdb_ip_lookup:action_result.data.*.data.domain", "!=", ""]
        ],
        name="filter_1:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_associated_domain(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["abuseipdb_ip_lookup:action_result.data.*.data.domain", "==", ""]
        ],
        conditions_dps=[
            ["abuseipdb_ip_lookup:action_result.data.*.data.domain", "==", ""]
        ],
        name="filter_1:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        no_domain_found(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def block_associated_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("block_associated_domain() called")

    # set approver and message variables for phantom.prompt call

    user = None
    role = "Administrator"
    message = """The IP {0} was found to be associated with the domain {1}."""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:ipaddress",
        "abuseipdb_ip_lookup:action_result.data.*.data.domain"
    ]

    # responses
    response_types = [
        {
            "prompt": "Would you also like to block this associated domain?",
            "options": {
                "type": "list",
                "required": True,
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=1440, name="block_associated_domain", parameters=parameters, response_types=response_types, callback=decision_1, drop_none=False)

    return


@phantom.playbook_block()
def no_domain_found(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("no_domain_found() called")

    template = """A domain for IP \"{0}\" was not found."""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:ipaddress"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="no_domain_found")

    add_note_to_soar_1(container=container)

    return


@phantom.playbook_block()
def add_note_to_soar_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_note_to_soar_1() called")

    no_domain_found = phantom.get_format_data(name="no_domain_found")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=no_domain_found, note_format="markdown", note_type="general", title="No Domain Associated")

    return


@phantom.playbook_block()
def prompt_action_description(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_action_description() called")

    ################################################################################
    # 2025-03-31	
    # PSAAS-22699	
    # action_result.summary.responder_email datapath is not populated
    ################################################################################

    template = """The user \"{2}\" approved blocking the domain \"{1}\" associated with the blocked IP \"{0}\"."""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:ipaddress",
        "abuseipdb_ip_lookup:action_result.data.*.data.domain",
        "block_associated_domain:action_result.summary.responder_email"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="prompt_action_description")

    add_note_to_soar(container=container)

    return


@phantom.playbook_block()
def add_note_to_soar(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_note_to_soar() called")

    prompt_action_description = phantom.get_format_data(name="prompt_action_description")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=prompt_action_description, note_format="markdown", note_type="general", title="Domain Associated")

    add_comment_to_soar(container=container)

    return


@phantom.playbook_block()
def cisco_ces_custom_domain_block(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("cisco_ces_custom_domain_block() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    command_formatted_string = phantom.format(
        container=container,
        template="""python3 /scripts/gms_cisco_ces_block_sender_domain.py {0}""",
        parameters=[
            "abuseipdb_ip_lookup:action_result.data.*.data.domain"
        ])

    abuseipdb_ip_lookup_result_data = phantom.collect2(container=container, datapath=["abuseipdb_ip_lookup:action_result.data.*.data.domain","abuseipdb_ip_lookup:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'cisco_ces_custom_domain_block' call
    for abuseipdb_ip_lookup_result_item in abuseipdb_ip_lookup_result_data:
        parameters.append({
            "command": command_formatted_string,
            "ip_hostname": "gms-scripts",
            "context": {'artifact_id': abuseipdb_ip_lookup_result_item[1]},
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("execute program", parameters=parameters, name="cisco_ces_custom_domain_block", assets=["ssh_automation"], callback=crowdstrike_custom_block_domain)

    return


@phantom.playbook_block()
def crowdstrike_custom_block_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("crowdstrike_custom_block_domain() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    command_formatted_string = phantom.format(
        container=container,
        template="""python3 /scripts/gms_crowdstrike_block_domain.py --value {0}""",
        parameters=[
            "abuseipdb_ip_lookup:action_result.data.*.data.domain"
        ])

    abuseipdb_ip_lookup_result_data = phantom.collect2(container=container, datapath=["abuseipdb_ip_lookup:action_result.data.*.data.domain","abuseipdb_ip_lookup:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'crowdstrike_custom_block_domain' call
    for abuseipdb_ip_lookup_result_item in abuseipdb_ip_lookup_result_data:
        parameters.append({
            "command": command_formatted_string,
            "ip_hostname": "gms-scripts",
            "context": {'artifact_id': abuseipdb_ip_lookup_result_item[1]},
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("execute program", parameters=parameters, name="crowdstrike_custom_block_domain", assets=["ssh_automation"], callback=cisco_firepower_custom_domain_block)

    return


@phantom.playbook_block()
def cisco_firepower_custom_domain_block(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("cisco_firepower_custom_domain_block() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    command_formatted_string = phantom.format(
        container=container,
        template="""python3 /scripts/gms_cisco_firepower_domain_block.py \"{0}\"""",
        parameters=[
            "abuseipdb_ip_lookup:action_result.data.*.data.domain"
        ])

    abuseipdb_ip_lookup_result_data = phantom.collect2(container=container, datapath=["abuseipdb_ip_lookup:action_result.data.*.data.domain","abuseipdb_ip_lookup:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'cisco_firepower_custom_domain_block' call
    for abuseipdb_ip_lookup_result_item in abuseipdb_ip_lookup_result_data:
        parameters.append({
            "command": command_formatted_string,
            "ip_hostname": "gms-scripts",
            "context": {'artifact_id': abuseipdb_ip_lookup_result_item[1]},
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("execute program", parameters=parameters, name="cisco_firepower_custom_domain_block", assets=["ssh_automation"], callback=cisco_umbrella_custom_domain_global_block_list)

    return


@phantom.playbook_block()
def cisco_umbrella_custom_domain_global_block_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("cisco_umbrella_custom_domain_global_block_list() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    command_formatted_string = phantom.format(
        container=container,
        template="""python3 /scripts/gms_umbrella_block_domain_global_block_list.py {0}\n""",
        parameters=[
            "abuseipdb_ip_lookup:action_result.data.*.data.domain"
        ])

    abuseipdb_ip_lookup_result_data = phantom.collect2(container=container, datapath=["abuseipdb_ip_lookup:action_result.data.*.data.domain","abuseipdb_ip_lookup:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'cisco_umbrella_custom_domain_global_block_list' call
    for abuseipdb_ip_lookup_result_item in abuseipdb_ip_lookup_result_data:
        parameters.append({
            "command": command_formatted_string,
            "ip_hostname": "gms-scripts",
            "context": {'artifact_id': abuseipdb_ip_lookup_result_item[1]},
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("execute program", parameters=parameters, name="cisco_umbrella_custom_domain_global_block_list", assets=["ssh_automation"], callback=cisco_umbrella_custom_domain_global_web_policy)

    return


@phantom.playbook_block()
def cisco_umbrella_custom_domain_global_web_policy(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("cisco_umbrella_custom_domain_global_web_policy() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    command_formatted_string = phantom.format(
        container=container,
        template="""python3 /scripts/gms_umbrella_block_domain_global_web_policy_block.py {0}""",
        parameters=[
            "abuseipdb_ip_lookup:action_result.data.*.data.domain"
        ])

    abuseipdb_ip_lookup_result_data = phantom.collect2(container=container, datapath=["abuseipdb_ip_lookup:action_result.data.*.data.domain","abuseipdb_ip_lookup:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'cisco_umbrella_custom_domain_global_web_policy' call
    for abuseipdb_ip_lookup_result_item in abuseipdb_ip_lookup_result_data:
        parameters.append({
            "command": command_formatted_string,
            "ip_hostname": "gms-scripts",
            "context": {'artifact_id': abuseipdb_ip_lookup_result_item[1]},
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("execute program", parameters=parameters, name="cisco_umbrella_custom_domain_global_web_policy", assets=["ssh_automation"], callback=trend_vision_one_block_domain)

    return


@phantom.playbook_block()
def trend_vision_one_block_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("trend_vision_one_block_domain() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    block_objects_formatted_string = phantom.format(
        container=container,
        template="""[{{\"object_type\": \"domain\", \"risk_level\": \"high\", \"expiry_days\": \"-1\", \"object_value\": \"{0}\"}}]""",
        parameters=[
            "abuseipdb_ip_lookup:action_result.data.*.data.domain"
        ])

    abuseipdb_ip_lookup_result_data = phantom.collect2(container=container, datapath=["abuseipdb_ip_lookup:action_result.data.*.data.domain","abuseipdb_ip_lookup:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'trend_vision_one_block_domain' call
    for abuseipdb_ip_lookup_result_item in abuseipdb_ip_lookup_result_data:
        if block_objects_formatted_string is not None:
            parameters.append({
                "block_objects": block_objects_formatted_string,
                "context": {'artifact_id': abuseipdb_ip_lookup_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add to suspicious", parameters=parameters, name="trend_vision_one_block_domain", assets=["trend micro vision one"])

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["block_associated_domain:action_result.summary.responses.0", "==", "yes"]
        ],
        conditions_dps=[
            ["block_associated_domain:action_result.summary.responses.0", "==", "yes"]
        ],
        name="decision_1:condition_1",
        case_sensitive=False,
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        prompt_action_description(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    no_or_not_answered(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def no_or_not_answered(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("no_or_not_answered() called")

    template = """The prompt to block the domain \"{0}\" was neither declined or not answered within the required response time."""

    # parameter list for template variable replacement
    parameters = [
        "abuseipdb_ip_lookup:action_result.data.*.data.domain"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="no_or_not_answered")

    add_note_to_soar_2(container=container)

    return


@phantom.playbook_block()
def add_note_to_soar_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_note_to_soar_2() called")

    no_or_not_answered = phantom.get_format_data(name="no_or_not_answered")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=no_or_not_answered, note_format="markdown", note_type="general", title="Response")

    return


@phantom.playbook_block()
def add_comment_to_soar(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_to_soar() called")

    prompt_action_description = phantom.get_format_data(name="prompt_action_description")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=prompt_action_description)

    cisco_ces_custom_domain_block(container=container)

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