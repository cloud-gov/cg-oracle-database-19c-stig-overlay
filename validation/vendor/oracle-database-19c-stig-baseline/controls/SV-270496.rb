control 'SV-270496' do
  title 'Oracle Database must protect against or limit the effects of organization-defined types of denial-of-service (DoS) attacks.'
  desc %q(DOS attacks, more correctly characterized as "Denial-of-Service Events" as they most often the result of run-away processes and accidents, are the result of an excessive demand for a limiting resource.

A variety of technologies exist to limit, or in some cases, eliminate the effects of DoS attacks. For example, boundary protection devices can filter certain types of packets to protect devices on an organization's internal network from being directly affected by DoS attacks but within the database itself, Oracle provides the following mechanisms:

1. Reduction of excessive concurrent connections from a single user (see STIG_ID O19C-00-000100).
2. Limiting the database connection rate (LISTENER.ORA).
3. Limiting the amount of CPU available to users with Profile kernel limits.
4. Limiting the amount of I/O available to users with Profile kernel limits.
5. Limiting the amount of storage space with tablespace quotas.
6. Limiting idle time with profile kernel limits.

Other best practices such as limiting the number of parallel handles available to users with Resource Manager Plans or using CMAN are also recommended as part of an overall plan for DoS prevention.)
  desc 'check', "Review database management system (DBMS) settings to verify the DBMS implements measures to limit the effects of a DoS event.

Rate Limit:

Check the $ORACLE_HOME/network/admin/listener.ora to verify a Rate Limit has been established. A rate limit is used to prevent DoS attacks on a database or to control a logon storm such as may be caused by an application server or pool restart.

If a rate limit has not been set similar to one of the two examples in Listing 1, this is a finding.
 
Listing 1
CONNECTION_RATE_LISTENER=10
LISTENER= (
  ADDRESS_LIST=
    (ADDRESS=(PROTOCOL=tcp)(HOST=)(PORT=1521)(RATE_LIMIT=yes))
    (ADDRESS=(PROTOCOL=tcp)(HOST=)(PORT=1522)(RATE_LIMIT=yes))
    (ADDRESS=(PROTOCOL=tcp)(HOST=)(PORT=1526))
           )
LISTENER=
  (ADDRESS_LIST=
    (ADDRESS=(PROTOCOL=tcp)(HOST=)(PORT=1521)(RATE_LIMIT=8))
    (ADDRESS=(PROTOCOL=tcp)(HOST=)(PORT=1522)(RATE_LIMIT=12))
    (ADDRESS=(PROTOCOL=tcp)(HOST=)(PORT=1526))
           )

Database Profiles:
If the database profiles, as shown in Listing 2 do not contain resource controls similar to those shown, but appropriate to the target database's infrastructure and utilization, that is a finding.

Listing 2
SELECT cp.con_id, cp.profile, cp.resource_name, cp.limit
FROM sys.cdb_profiles cp
WHERE resource_name IN ('CPU_PER_CALL', 'IDLE_TIME', 'LOGICAL_READS_PER_CALL');
ORDER BY 1,2,3;


Tablespace Quota:

Listing 3
SELECT ctq.con_id, ctq.tablespace_name, ctq.username, ctq.max_bytes, ctq.max_blocks
FROM sys.cdb_ts_quotas ctq
WHERE ((max_bytes = -1) OR (max_blocks = -1))
AND (ctq.con_id, ctq.tablespace_name) IN (SELECT ct.con_id, ct.tablespace_name FROM sys.cdb_tablespaces ct)
ORDER BY 1;

If any rows returned have a MAX_BYTES or MAX_BLOCKS equal to minus one (-1) that is a finding."
  desc 'fix', 'Implement measures to limit the effects of organization-defined types of DoS attacks.

For each of the three queries in the Check, if there are findings, make the changes required to bring the environment into compliance.

For Listing 1:
Modify the $ORACLE_HOME/network/admin/listener.ora to establish a Rate Limit.
Restart the listener for changes to take effect.

For Listing 2:
Set limits on all profiles for CPU_PER_CALL, IDLE_TIME, and LOGICAL_READS_PER_CALL.

For Listing 3:
Enforce reasonable limits for tablespace consumption sufficient to prevent a DOS attack from impacting multiple applications or multiple services.'
  impact 0.5
  tag gtitle: 'SRG-APP-000001-DB-000031'
  tag gid: 'V-270496'
  tag rid: 'SV-270496r1167727_rule'
  tag stig_id: 'O19C-00-000200'
  tag fix_id: 'F-74430r1167726_fix'
  tag cci: ['CCI-002385', 'CCI-000054']
  tag nist: ['SC-5', 'Rev_4', 'AC-10']
  tag 'false_negatives'
  tag 'false_positives'
  tag 'documentable'
  tag 'mitigations'
  tag 'severity_override_guidance'
  tag 'potential_impacts'
  tag 'third_party_tools'
  tag 'mitigation_controls'
  tag 'responsibility'
  tag 'ia_controls'
  tag 'check'
  tag 'fix'

  oracle_home = command('echo $ORACLE_HOME').stdout.strip

  describe file "#{oracle_home}/network/admin/listener.ora" do
    its('content') { should include 'RATE_LIMIT=' }
    its('content') { should match /CONNECTION_RATE_LISTENER=\d*/ }
  end
end
