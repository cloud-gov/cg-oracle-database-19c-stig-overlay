control 'SV-270558' do
  title 'Oracle Database must be configured to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL) and vulnerability assessments.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols/services on information systems.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

Database Management Systems using ports, protocols, and services deemed unsafe are open to attack through those ports, protocols, and services. This can allow unauthorized access to the database and through the database to other components of the information system.

'
  desc 'check', 'Review the database management system (DBMS) settings for unapproved functions, ports, protocols, and services.

If any are found, this is a finding.

For definitive information on PPSM, refer to https://cyber.mil/ppsm/.

- - - - -

In the Oracle database, the communications with the database and incoming requests are performed by the Oracle Listener. The Oracle Listener listens on a specific port or ports for connections to a specific database. The Oracle Listener has configuration files located in the $ORACLE_HOME/network/admin directory. To check the ports and protocols in use, go to that directory and review the SQLNET.ora, LISTENER.ora, and the TNSNAMES.ora. If protocols or ports are in use that are not authorized, this is a finding.'
  desc 'fix', 'Disable functions, ports, protocols, and services that are not approved.

- - - - -
Change the SQLNET.ora, LISTENER.ora, and TNSNAMES.ora files to reflect the proper use of ports, protocols, and services that are approved at the site.

If changes to the Listener are made, the files associated with the Listener must be reloaded by issuing the following commands at the Unix/Linux or Windows prompt.

Issue the command to verify what the current status is:
$ lsnrctl stat

Load the new file that was corrected to reflect site-specific requirements:
$ lsnrctl reload

Check the status again to verify that the changes have taken place:
$ lsnrctl stat'
  impact 0.5
  tag check_id: 'C-74591r1064950_chk'
  tag severity: 'medium'
  tag gid: 'V-270558'
  tag rid: 'SV-270558r1065283_rule'
  tag stig_id: 'O19C-00-013500'
  tag gtitle: 'SRG-APP-000142-DB-000094'
  tag fix_id: 'F-74492r1065282_fix'
  tag satisfies: ['SRG-APP-000142-DB-000094', 'SRG-APP-000383-DB-000364']
  tag 'documentable'
  tag cci: ['CCI-000382', 'CCI-001762']
  tag nist: ['CM-7 b', 'CM-7 (1) (b)']

  # OVERLAY-ADDED (MANUAL-REVIEW, overlay #6): upstream shipped this as an empty stub
  # (silent pass). Marked as an explicit review so it can never silently pass.
  describe 'ports/protocols usage is a configuration/policy review' do
    skip 'ports/protocols usage is a configuration/policy review'
  end
end
