"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'block_domain_child_playbook' block
    block_domain_child_playbook(container=container)

    return

@phantom.playbook_block()
def block_domain_child_playbook(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("block_domain_child_playbook() called")

    # set approver and message variables for phantom.prompt call

    user = None
    role = "Administrator"
    message = """Initiating Domain Blocking \"{0}\" .."""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:domain"
    ]

    # responses
    response_types = [
        {
            "prompt": "Do you want to block this domain?",
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

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="block_domain_child_playbook", parameters=parameters, response_types=response_types, callback=decision_1, drop_none=True)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["block_domain_child_playbook:action_result.summary.responses.0", "==", "yes"]
        ],
        conditions_dps=[
            ["block_domain_child_playbook:action_result.summary.responses.0", "==", "yes"]
        ],
        name="decision_1:condition_1",
        case_sensitive=False,
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        prompt_action_description(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    decision_no_domain_blocking_formatting(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def crowdstrike_custom_block_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("crowdstrike_custom_block_domain() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    command_formatted_string = phantom.format(
        container=container,
        template="""python3 /scripts/gms_crowdstrike_block_domain.py --value {0}""",
        parameters=[
            "filtered-data:filter_1:condition_1:playbook_input:domain"
        ])

    filtered_input_0_domain = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:playbook_input:domain"])

    parameters = []

    # build parameters list for 'crowdstrike_custom_block_domain' call
    for filtered_input_0_domain_item in filtered_input_0_domain:
        parameters.append({
            "command": command_formatted_string,
            "ip_hostname": "gms-scripts",
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
            "filtered-data:filter_1:condition_1:playbook_input:domain"
        ])

    filtered_input_0_domain = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:playbook_input:domain"])

    parameters = []

    # build parameters list for 'cisco_firepower_custom_domain_block' call
    for filtered_input_0_domain_item in filtered_input_0_domain:
        parameters.append({
            "command": command_formatted_string,
            "ip_hostname": "gms-scripts",
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
        template="""python3 /scripts/gms_umbrella_block_domain_global_block_list.py {0}""",
        parameters=[
            "filtered-data:filter_1:condition_1:playbook_input:domain"
        ])

    filtered_input_0_domain = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:playbook_input:domain"])

    parameters = []

    # build parameters list for 'cisco_umbrella_custom_domain_global_block_list' call
    for filtered_input_0_domain_item in filtered_input_0_domain:
        parameters.append({
            "command": command_formatted_string,
            "ip_hostname": "gms-scripts",
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
            "filtered-data:filter_1:condition_1:playbook_input:domain"
        ])

    filtered_input_0_domain = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:playbook_input:domain"])

    parameters = []

    # build parameters list for 'cisco_umbrella_custom_domain_global_web_policy' call
    for filtered_input_0_domain_item in filtered_input_0_domain:
        parameters.append({
            "command": command_formatted_string,
            "ip_hostname": "gms-scripts",
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
        template="""[{{\"object_type\": \"domain\", \"risk_level\": \"high\", \"expiry_days\": \"-1\", \"object_value\": \"{0}\"}}]\n""",
        parameters=[
            "filtered-data:filter_1:condition_1:playbook_input:domain"
        ])

    filtered_input_0_domain = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:playbook_input:domain"])

    parameters = []

    # build parameters list for 'trend_vision_one_block_domain' call
    for filtered_input_0_domain_item in filtered_input_0_domain:
        if block_objects_formatted_string is not None:
            parameters.append({
                "block_objects": block_objects_formatted_string,
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
def decision_no_domain_blocking_formatting(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_no_domain_blocking_formatting() called")

    template = """User \"{1}\" decided not to block domain \"{0}\" .."""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:domain",
        "block_domain_child_playbook:action_result.summary.responder_email"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="decision_no_domain_blocking_formatting", drop_none=False)

    add_note_to_soar(container=container)

    return


@phantom.playbook_block()
def add_note_to_soar(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_note_to_soar() called")

    decision_no_domain_blocking_formatting = phantom.get_format_data(name="decision_no_domain_blocking_formatting")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=decision_no_domain_blocking_formatting, note_format="markdown", note_type="general", title="Decided Not To Block Domain")

    return


@phantom.playbook_block()
def prompt_action_description(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_action_description() called")

    template = """The user \"{0}\" approved blocking the domain \"{1}\"."""

    # parameter list for template variable replacement
    parameters = [
        "block_domain_child_playbook:action_result.summary.responder_email",
        "playbook_input:domain"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="prompt_action_description")

    add_note_to_soar_1(container=container)

    return


@phantom.playbook_block()
def add_note_to_soar_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_note_to_soar_1() called")

    prompt_action_description = phantom.get_format_data(name="prompt_action_description")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=prompt_action_description, note_format="markdown", note_type="general", title="Decided To Block Domain")

    add_comment_to_soar(container=container)

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

    crowdstrike_custom_block_domain(container=container)

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