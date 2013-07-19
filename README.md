p3
==

An open source pcap packet and NetFlow file analysis tool using Hadoop MapReduce and Hive.

This project joins pcap-on-hadoop (https://github.com/ssallys/pcap-on-Hadoop) 
 and nflow-on-hadoop(https://github.com/ssallys/nflow-on-Hadoop).

---------------
Installation
---------------

1. To install Apache Hadoop

   http://www.michael-noll.com/tutorials/running-hadoop-on-ubuntu-linux-multi-node-cluster/

2. To install Apache Hive

   https://cwiki.apache.org/confluence/display/Hive/GettingStarted

---------------
Confiuration
---------------

1. put p3-default.xml to $HADOOP_HOME/conf

   This file is currently not used, but some code is not modified.

   This file includes:

            <property>
                            <name>pcap.file.captime.min</name>
                            <value>1168300867</value>
                            <description>stop time of packet capturing</description>
            </property>
            <property>
                            <name>pcap.file.captime.max</name>
                            <value>1168387267</value>
                            <description>stop time of packet capturing</description>
            </property>

------------
IP Analysis
------------

1. Total traffic and host/port count statistics

   hadoop jar ./p3.jar p3.runner.PcapTotalStats -r[source dir/file] -n[reduces]

2. Periodic flow statistics

   hadoop jar ./p3.jar p3.runner.PcapTotalFlowStats -r[source dir/file] -n[reduces] -p[period]

3. Periodic simple traffic statistics

   hadoop jar ./p3.jar p3.runner.PcapStats -r[source dir/file] -n[reduces]
   
------------
NetFlow Analysis
------------

1. Total traffic statistics for NetFlow data

   hadoop jar ./p3.jar nflow.runner.Runner -r[source dir/file] -n[reduces] -js
   