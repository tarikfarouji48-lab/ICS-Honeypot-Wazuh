FROM tomcat:7-jre8
RUN rm -rf /usr/local/tomcat/webapps/*
COPY ScadaBR.war /usr/local/tomcat/webapps/ScadaBR.war
EXPOSE 8080
CMD ["catalina.sh", "run"]
