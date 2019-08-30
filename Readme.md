1. Copy atlassian-extras-3.2.jar to folder  atlassian-jira-software-8.3.2-standalone/atlassian-jira/lib  
and  copy atlassian-universal-plugin-manager-plugin-4.0.1.jar to folder atlassian-jira-software-8.3.2-standalone/atlassian-jira/atlassian-bundled-plugins/ 
2. Config home folder for jira: vi classes/jira-application.properties 
jira.home = /opt/atlassian/jira/
2. Start jira server     atlassian-jira-software-8.3.2-standalone/bin/start-jira.sh 
3. Copy Server ID vao file: license_key.txt
4. Run command:  php atlassian-keygen.php -e license_key.txt 
5. Copy key generate in console
