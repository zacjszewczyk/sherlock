# SHERLOCK Generate Playbooks with Agent

The SHERLOCK project creates structured analysis playbooks, based on analysis plans, that tell defenders not only what to look for but where and why. I will first explain the format and components of the existing analysis plans, then the format and components of the analysis playbooks we must create, and then finally provide you specific instructions for building the analysis plans. For this task, exclusively limit your work to the “./sherlock/“ and “./watson/“ directories only. 

## Analysis Plans

Analysis plans are stored in JSON files based on a specific MITRE technique, saved in the “watson/techniques/“ folder and its subdirectories, and are structured as follows:

```
[
  {
    “information_requirement”: “<Mission question or CCIR, phrased as a question. This identifies the information that the commander considers most important.>”,
    “tactic_id”: “<TA### tactic ID>”,
    “tactic_name”: “<tactic name, from MITRE>”,
    “tactic_description”: “<summary of tactic, from MITRE>”,
    “tactic_url”: “<MITRE ATT&CK/D3FEND link>”,
    “tactic_created”: “<created timestamp, from MITRE>”,
    “tactic_last_modified”: “<last modified timestamp, from MITRE>”,
    “tactic_domain”: [“<list of domains, from MITRE>”],
    “tactic_version”: “<version number, from MITRE>”,
    “indicators”: [
      {
        “technique_id”: “<T#### technique ID>”,
        “technique_name”: “<technique name, from MITRE>”,
        “technique_description”: “<summary of technique, from MITRE>”,
        “technique_url”: “<MITRE ATT&CK/D3FEND link>”,
        “technique_created”: “<created timestamp, from MITRE>”,
        “technique_last_modified”: “<last modified timestamp, from MITRE>”,
        “technique_domain”: [“<list of domains, from MITRE>”],
        “technique_version”: “<version number, from MITRE>”,
        “technique_platforms”: [“<list of platforms, from MITRE>”],
        “technique_analytics”: {
          “<AN#### analytic ID, from MITRE>”: {
            “analytic_name”: “<name of analytic, from MITRE>”,
            “analytic_description”: “<description of analytic, from MITRE>”,
            “analytic_url”: “<MITRE analytic link>”,
            “analytic_created”: “<created timestamp, from MITRE>”,
            “analytic_last_modified”: “<last modified timestamp, from MITRE>”,
            “analytic_domain”: [“<list of domains, from MITRE>”],
            “analytic_version”: “<version number, from MITRE>”,
            “analytic_log_source_references”: [
              {
                “data_component_id”: “<DC#### data component ID, from MITRE>”,
                “data_component_title”: “<data component title, from MITRE>”,
                “log_source_name”: “<log source name, from MITRE>”,
                “log_source_channel”: “<log source channel or filter, from MITRE>”
              }
            ]
          }
        },
        “detection_strategies”: {
          “<DET#### detection strategy ID, from MITRE>”: {
            “detection_strategy_name”: “<detection strategy name, from MITRE>”,
            “detection_strategy_url”: “<MITRE detection strategy link>”,
            “detection_strategy_created”: “<created timestamp, from MITRE>”,
            “detection_strategy_last_modified”: “<last modified timestamp, from MITRE>”,
            “detection_strategy_domain”: [“<list of domains, from MITRE>”],
            “detection_strategy_version”: “<version number, from MITRE>”
          }
        },
        “evidence”: [
          {
            “description”: “<Observable detail. This is the concrete information that supports or refutes an indicator. It provides the ‘proof’ and can vary in complexity.>”,
            “data_sources”: [“<List of data sources that would contain the evidence of the indicator as it manifests under the parent tactic. This describes the precise data necessary to identify evidence. Specificity here is key (e.g., Zeek Conn logs, Sysmon event ID 4624, Active Directory security logs).”],
            “data_platforms”: [“<Use a dummy value here of ‘TBD’.>”],
            “nai”: “<These are areas where data that will satisfy a specific information requirement can be collected.>”,
            “action”: {
              “<summary of symbolic logic action>”: “Symbolic Logic: <description>”,
              “<summary of statistical method action>”: “Statistical Method: <description>”,
              “<summary of machine learning action>”: “Machine Learning: <description>”
            }
          }
        ]
      }
    ],
    “last_updated”: “<date analytic plan was last updated>”,
    “version”: “<plan version>”,
    “date_created”: “<date analytic plan was created>”,
    “contributors”: [“List of names of contributors”]
  }
]
```

Here is a description of each component of the analytic plan. Note: the components of the analytic plan that are tagged “from MITRE” are retrieved directly from the MITRE ATT&CK matrix and stored in the analysis plan as-is; consider them read-only context for the analysis plan. 

1. CCIRs: These identify the information that the commander considers most important. For example, ‘Has the adversary gained initial access? (TA0001 - Initial Access)’ (PIR) or ‘What data is available for threat detection and modeling? (D3-D - Detect)’ (FFIR). Note that PIRs are tagged with a MITRE ATT&CK tactic, and FFIRs are tagged with a MITRE D3FEND tactic. We call these “CCIR” generally, although may refer to them as “information requirements” (IR) as well. 
2. Indicators: These are positive or negative evidence of threat activity pertaining to one or more information requirements. They are observable clues related to a specific information requirement. For the IR above, indicators might include:
    * T1078 - Valid Accounts
   For the FFIR above, indicators might include:
    * D3-NTA - Network Traffic Analysis
   Note that indicators for PIRs are tagged with MITRE ATT&CK techniques, and the indicators for FFIRs are tagged with MITRE D3FEND techniques.
3. Evidence: This is the concrete information that supports or refutes an indicator. It provides the ‘proof’ and can vary in complexity. For the indicator ‘T1078 - Valid Accounts’, evidence could be ‘A valid account login exhibits multiple anomalous characteristics simultaneously, such as originating from a rare geographic location, using an unfamiliar device, and occurring outside of normal working hours.’ For the indicator ‘D3-NTA’, evidence could be ‘Logs generated from network activity such as network flow metadata and network traffic content’.
4. Data: This describes the precise data necessary to identify evidence. Specificity here is key (e.g., Zeek Conn logs, Sysmon event ID 4624, Active Directory security logs). For the evidence, focus your plan on the following data sources: network logs, specifically Zeek logs; host logs, specifically Windows Event IDs. Write only the data name. For example, Windows Event ID 4688, Zeek conn.log. Note that while we generally want to rely on endpoint logs (Windows event logs, Unix auditd logs) and network logs (Zeek, PCAP) for data sources, there are many techniques that are not detectable using those data sources, such as cloud-based techniques. Ensure that each analytic plan identifies appropriate data sources to detect each manifestation of the identified technique, under the parent tactic. 
5. Data Platform: Use a dummy value here of “TBD”.
6. Named Areas of Interest (NAIs): These are areas where data that will satisfy a specific information requirement can be collected. For the IR above, NAIs could include ‘Our organization’s internet gateway’, ‘Authentication servers’, ‘Servers hosting sensitive data’, and ‘Endpoint devices of high-value targets’.
7. Actions. These are high-level instructions that guide the analysts’ search for evidence. For the evidence associated with the indicator ‘T1078 - Valid Accounts’ and the associated PIR ‘Has the adversary gained initial access? (TA0001 - Initial Access)’, an action could be: ‘For each successful login (Windows Event ID 4624), enrich with geolocation data from the source IP (Zeek conn.log). Establish a multi-faceted baseline for each user account including typical login times, source countries/ISPs, and devices used. Use a scoring system where deviations from the baseline (e.g., rare country, login at 3 AM, new device) add to a risk score. A high cumulative risk score, identified using statistical models or descriptive statistics (e.g., multiple metrics exceeding 2 standard deviations from the norm), indicates a likely compromised account.’ For the evidence associated with the indicator ‘D3-NTA’ and the associated FFIR ‘What data is available for threat detection and modeling? (D3-D - Detect)’, an action could be: ‘Inventory available network log sources (e.g., networking appliances, Zeek, PCAP). For each source, perform a time series analysis to visualize data volume over at least the last 30 days to identify collection gaps or anomalies. Use descriptive statistics to summarize key fields like protocol distribution in Zeek conn.log and the frequency of top requested domains in dns.log to establish a cursory understanding of network activity. Compare across data sources to validate collection consistency and identify individual sensor blind spots.’ Actions should be robust and clearly articulated, moving beyond simple keyword searches to span the gamut of MITRE’s Analytic Characterization Framework—for example, incorporating symbolic logic (detection rules), statistical methods (baselines and anomaly detection), and machine learning where appropriate. Actions in an analytic plan are a floor, not a ceiling; experienced analysts will extend them based on their knowledge, tools, and the evolving situation. You should have at least one symbolic logic (such as an IOC match), at least one statistical method (such as a percentile threshold), and at least one machine learning application (such as classification or time series analysis) action. Note that you may have more than one of each to present the analyst with a rigorous detection strategy that could be rigorously defensible. These detection strategies must be realistically capable of detecting the given technique as it would manifest under each specific tactic (e.g. detecting valid accounts for persistence is different than for initial access, etc.)

Note that there is one file per MITRE ATT&CK technique, but since an individual technique may appear as part of multiple parent tactics, there may be more than one manifestation of that technique per file to account for multiple parent tactics. This is reflected in the JSON file’s LIST structure.

## Analysis Playbooks

Analysis playbooks consists of the following components in a YAML format. These files do not yet exist, but will be created and then stored in “sherlock/techniques” and its sub-directories to match the layout of the analysis plans in “watson/“:

```
* Playbook Name [name]: A short, descriptive name for the playbook. This should be the “technique_id” and “technique_name” in the format “technique_id: technique_name” from the playbook.
* Playbook ID [id]: A unique identifier for the playbook. The identifier should use the UUID Version 4 format. 
* Playbook Description [description]: A longer description of the playbook. This description can include useful investigative context for the playbook that is not captured in the other fields. Derive this from the "evidence" element of the analysis plan.
* Playbook Type [type]: The category of playbook. For standalone playbooks, this can either be artifact, technique, phase, or malware. Since this playbook is based off of a MITRE ATT&CK technique (indicator), use “technique” for this field.
* Related Playbooks [related]: References to other playbooks that may be useful in investigating observations commonly tied to this playbook. Insert the “tactic_id” and “tactic_name” here.
* Playbook Contributors [contributors]: A list of people who contributed to the playbook, beginning with the original author. Derive this from a comma-joined list of “contributors” from the analysis plan JSON file.
* Created Date [created]: The date the playbook was initially created on. Use the date in YYYY-MM-DD format.
* Last Modified Date [modified]: The most recent date when the playbook was added to or modified. Use the date in YYYY-MM-DD format.
* Version [version]: The version of the playbook.
* Tags [tags]: Additional categorization properties. For now, leave this as “none”.
* Investigative Questions [questions]: The investigative question that the play should help answer. A playbook may contain multiple questions. Each question has properties associated with it.
    * Question [question]: The investigative question written in plain but detailed language for human consumption, in the form of a question. Derive one question from each “action” element.
        * Context [context]: A detailed description of the question purpose or rationale. Use this field to describe why the question is meaningful or why the analyst should care about its answer. Expound upon the “action” element here with thorough, helpful detail.
        * Answering Data Sources [answer_sources]: The data sources that can be used to answer the question. Derive this from the “data_sources” and “nai” keys.
        * Relative Time Range [range]: The time range for which evidence data should be examined to answer the question. The range should be expressed in terms relative to the observed event time, if applicable. Default to the last 90 days unless that is infeasible or unless a different value is more appropriate.
        * Queries [queries]: Search queries analysts can use to gather evidence data to answer the question. Specify the search technology and the query. For now, output short pseudocode based on the approach described in the action.
```

Note that you must output a distinct “question”, “context”, “answer_sources”, “range”, and “queries” series for each distinct action in the analytic plan. Your "question" and "context" should be a more helpful, verbose, and explanatory version of the "action" from the analysis plan, designed to help guide an analyst to investigate what may be a high-level abstraction in the brief analysis plan. The playbooks should provide very granular, actionable guidance to analysts.

## Instructions

I need you to first carefully review the README file of “watson/“ and “sherlock/“ to understand these projects' functionality. Next, carefully review the “techniques/“ folders in each project to understand the current state of the code base.

Based on the definitions of an analysis plan (watson; already exists) and an analysis playbook (sherlock; does not exist yet), please generate an analytic playbook in plain, unstyled text in the YAML format based on the guidance below.

You are **Agent #1**. Keep track of all work and progress as this Agent in the “sherlock/tools/prompts/enterprise-techniques.md” file, and do not do any work assigned to another Agent!

For this task, I need you to manually (without a script) generate an analysis playbook in the "sherlock/" project, based on the corresponding analysis plan in the "watson/" project, to help cybersecurity analysts identify the specified technique. Do not make any changes to the "watson/" repository, and the only change you may make to the "sherlock/" repository is to create new plans in a YAML format, under "techniques/", and to update the shared context file “sherlock/tools/prompts/enterprise-techniques.md”. Do not make other changes to the repository. Note that my threat model primarily consists of a sophisticated external threat attempting to gain unauthorized access to my organization’s sensitive data, although I must also account for more run of the mill threat actors, routine malware, and insider threats. 

This is the workflow I need you to follow for each technique file listed under your Agent section of the “sherlock/tools/prompts/enterprise-techniques.md” file. Do not alter files that other agents are working on in parallel, listed in their sections.

1. If the technique is marked as “Complete”, ignore it and do not make any changes.
2. If the technique is marked as “In Progress”, in the section for your Agent (such as “##### Agent #1 Techniques”, “##### Agent #2 Techniques”, or “##### Agent #3 Techniques”), carefully review the source analysis plan, then generate a new analysis playbook in the "sherlock/" project based on the structure described above. Once you have created the analysis playbook, move the technique from your portion of the “In Progress” section to the bottom of the “Complete” section in the “sherlock/tools/prompts/enterprise-techniques.md” file. Once the “In Progress” technique is moved from your Agent section to “Complete”, be sure to remove it from the “Not Processed” section if it is also listed there.
3. Ensure the"created" and "modified" date of the analysis playbook you created is “2026-02-18”, and ensure the "version" is 1.0.
4. After each batch of techniques is complete, provide me with a summary of the changes made to each technique file in that batch, and then commit the changes to the repository with a generic commit message based on the summary and the date-time group of the completion.
5. Once you have completed your Agent’s tasks, leave the section header and description intact, and insert “(no active Agent #X tasks right now)”, where X is your agent number.

It is imperative that you keep accurate track of your assigned techniques, based on your Agent designation and the clearly marked sections in the “sherlock/tools/prompts/enterprise-techniques.md” file, and their status using the enterprise-techniques.md files, where the names of the techniques must be stored in the appropriate sections. Only track your assigned techniques. Remember not to remove any information from the actions as you refactor them. Note that since other agents may be working on this directory at the same time, you may observe changes that you did not make; focus only on your Agent tasks.