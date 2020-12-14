Data Plane Key Management (DPKM)
====================================
This GitHub Repository contains extensions to the Floodlight Controller for integration of the Data Plane Key Management scheme DPKM.
DPKM enables automated configuration of WireGuard network tunnels between nodes in the data plane. Floodlight has been extended with a new package located in [net.floodlightcontroller.dpkmconfigurewg](https://github.com/lukehengstenberg/DPKM_Floodlight/tree/master/src/main/java/net/floodlightcontroller/dpkmconfigurewg).
Eight procedures have been added for Configuring WireGuard, Unconfiguring WireGuard, Adding Peers, Deleting Peers, Starting Encrypted Communication, Ending Encrypted Communication, Rekeying, and Compromise/Key Revocation. New REST APIs were defined for initiating all procedures from the UI.
OpenFlow has been extended with Loxigen to include six new messages, a new OXM, and fifteen new error messages. <br />
DPKM relies on modified OVS nodes set-up from [Here](https://github.com/lukehengstenberg/DPKM_OVS), and an extended Floodlight-webui which is included as a submodule located [Here](https://github.com/lukehengstenberg/DPKM_Floodlight-webui).<br /><br /> 

DPKM was completed as part of an MSc project at Swansea University and is still a work in progress.
Extensive testing with multiple nodes is needed since the project was built and tested for a single controller with two nodes. The project database is also poorly packaged and will only work from Eclipse, not the jar file. The project would benefit from a professionals expertise to clean-up code and integrate better native support.<br /><br />
For any questions or queries, contact the developer at this [email](mailto:lukehengstenberg@gmail.com)!

DPKM Floodlight Controller Setup Instructions
=============================================
1. Install Ubuntu 18.04.
2. Install Java Development Kit 8 and change current jdk version to 8. Follow [this](https://docs.datastax.com/en/jdk-install/doc/jdk-install/installOpenJdkDeb.html) guide for help installing java/changing version. The java version can be changed with the command: ```update-alternatives --config java```.
3. Install the Floodlight dependencies by running the command: ```apt-get install git build-essential ant maven python-dev```.
4. CD into the desired directory and download the source code from github: ```git clone git://github.com/lukehengstenberg/DPKM_Floodlight.git```.
5. From this point onwards the downloaded DPKM_Floodlight folder will be referred to as floodlight. Rename the folder for convenience.
6. Before Floodlight can be used the cntrldb database needs to be created. Install MySQL server with the command: ```apt-get install mysql-server```.
7. Check MySQL is running with ```sudo service mysql status```. If down start with ```service mysql start```.
8. Login to MySQL with ```mysql -u root -p```, entering root password when prompted.
9. Run the command ```CREATE DATABASE cntrldb;``` to recreate the database.
10. Create the floodlight user with the command: ```CREATE USER ‘floodlight’@’localhost’ IDENTIFIED BY ‘FLPass878876#’;```. If new credentials are to be used, modify the following file to store the new url, user, and password floodlight/src/main/resources/db.properties.
11. Select the database with ```USE cntrldb;``` and grant database access permissions to floodlight with ```GRANT ALL ON cntrldb.* TO ‘floodlight’@’localhost’;```.
12. Use ```exit``` to return to command line. CD into floodlight and run the command: ```mysql -u floodlight -p cntrldb < cntrldb.sql``` to create the three tables CommunicatingPeers, ConfiguredPeers, and ErrorLog.
13. Log back into mysql as floodlight with ```mysql -u floodlight -p|```, run ```USE cntrldb;```, followed by ```SHOW TABLES;``` to confirm the three tables have been created. Use ```DESCRIBE``` to see table schema.
14. CD back into floodlight and run ```git submodule init```, ```git submodule update```, ```ant``` to build the floodlight.jar file and automatically pull the UI from the [repo](git://github.com/lukehengstenberg/DPKM_Floodlight-webui).
15. If an error is thrown at this point remove the ```/floodlight/src/main/resource/web directory``` and run ```git submodule sync``` followed by ```git submodule update --init```.
16. Make a new local directory with ```mkdir /var/lib/floodlight``` and set access permissions with ```chmod 777 /var/lib/floodlight```.
17. Running the command ```java -jar target/floodlight.jar``` can now launch the controller. HOWEVER, in its current prototype state this method means the DPKM UI cannot reach the cntrldb database, throwing an error. To use the UI for DPKM procedures the project MUST be setup and run from eclipse.
18. Download the eclipse IDE with ```snap install --classic eclipse```.
19. Follow the instructions on the official floodlight [website](https://floodlight.atlassian.net/wiki/spaces/floodlightcontroller/pages/1343544/Installation+Guide\#InstallationGuide-EclipseIDE) to create the eclipse project setup files, import floodlight as an existing project into a new workspace, and run the controller.
20. Troubleshooting: The first attempt at building the project in eclipse may produce the error “The project was not built due to X being marked read-only”. This can be solved by changing the workspace folder to have write access permissions or selecting another build path.
21. Now that the controller is running the GUI should be deployed. Use a web browser to navigate to the URL ```http://<controller-ip>:8080/ui/pages/index.html```. The DPKM page can then be reached through the navbar or ```/dpkm.html```.
22. The Floodlight/UI setup is now complete! The dpkm source code can be viewed and extended by navigating to the src/main/java folder and exploring the ```net.floodlightcontroller.dpkmconfigurewg package```. Extending the UI will require the repository to be cloned into a separate folder and opened in a text editor/IDE suited to web development.
23. Next: Follow these [instructions](https://github.com/lukehengstenberg/DPKM_OVS) to set up the OVS node on another VM.

Floodlight OpenFlow Controller (OSS)
====================================

Attention!
----------

As of August 2018, the Floodlight mailing list has moved to [floodlight@groups.io](mailto:floodlight@groups.io)! Archives and the new group home page [can be found here](https://groups.io/g/floodlight). Please see [Documentation and Support](#Documentation-and-Support) below for up-to-date support information.

Build Status
------------

[![Build Status](https://travis-ci.org/floodlight/floodlight.svg?branch=master)](https://travis-ci.org/floodlight/floodlight)

What is Floodlight?
-------------------

Floodlight is the leading open source OpenFlow controller. It is [supported by a community of developers](https://floodlight.atlassian.net/wiki/display/floodlightcontroller/Authors+and+Contributors), including a number of engineers from [Big Switch Networks](http://www.bigswitch.com/).

What is OpenFlow?
-----------------

OpenFlow is a open standard managed by Open Networking Foundation. It specifies a protocol by which a remote controller can modify the behavior of networking devices through a well-defined “forwarding instruction set”. Floodlight is designed to work with the growing number of switches, routers, virtual switches, and access points that support the OpenFlow standard.

Getting Started
---------------

The quickest way to use Floodlight is to start with our [pre-built VM](https://floodlight.atlassian.net/wiki/spaces/floodlightcontroller/pages/8650780/Floodlight+VM), which includes the controller, IDE, and everything you need to use Floodlight and/or start developing. You can also deploy and develop with Floodlight [in your own environment](https://floodlight.atlassian.net/wiki/spaces/floodlightcontroller/pages/1343544/Installation+Guide).

If you are a developer and are looking for project ideas, please take a look at [our current issues](https://github.com/floodlight/floodlight/issues). They are a great way to get started developing with Floodlight and provide a concrete way in which to [give back](#Contribution)!

Documentation and Support
-------------------------

Ready to get started using Floodlight? The [Floodlight wiki](https://floodlight.atlassian.net/wiki/spaces/floodlightcontroller/overview) contains user and developer documentation, as well as helpful tutorials from beginner to advanced.

Do you have a question, comment, or a great idea you'd like to propose to the community? Please subscribe and send to our mailing list [floodlight@groups.io](mailto:floodlight@groups.io). Archives and additional content can be found on the [group homepage](https://groups.io/g/floodlight).

Contribution
------------

Floodlight is supported by contributions from developers like yourself. If you found and fixed something that needed attention or have added a feature, please consider giving back by [opening a pull request](https://github.com/floodlight/floodlight/pulls). We value each and every contribution, no matter how large or how small.

If you have found a bug or have a feature request, please send a note to [floodlight@groups.io](mailto:floodlight@groups.io) and [open a issue](https://github.com/floodlight/floodlight/issues) to track it. If you are able to give back by addressing the issue yourself, please read the above and thank you! If you are unable to contribute a solution, following these simple steps will allow someone the opportunity to do so.

Interested in contributing but don't know where to start? Check out and consider addressing any of [our current issues](https://github.com/floodlight/floodlight/issues).

Authors and Contributors
------------------------

Thank you to [all who have contributed](https://floodlight.atlassian.net/wiki/display/floodlightcontroller/Authors+and+Contributors) to Floodlight! Please reach out if we have missed you, so that you can be added to this growing list.

