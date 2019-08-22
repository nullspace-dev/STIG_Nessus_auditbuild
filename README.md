#Author brad McMahon (nullspace)

# STIG Nessus AuditBuild
This tool is helpful in building a nearly complete Nessus Audit file from a STIG (Security Technical Implementation Guide) file. There are a number of STIGS that are not covered by Tenable's releases and this hopefully helps you if you need one of those. Keep in mind this builds the bulk of the Audit File but not the meat which is namely the regex used to id if the the security measure is compliance or not. 

TLDR:
builds a baseline nessus audit file from a  STIG. The regex still needs to be added by hand but this saves a lot of work.
