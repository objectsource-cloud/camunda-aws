# Camunda Deployment on Amazon Web Services using the AWS SDK for Java

This project was inspired by the blog article 
[Deploy a Camunda BPM Docker Image with Amazon Web Services](https://blog.camunda.com/post/2015/06/deploy-camunda-bpm-docker-image-with/) and aims to automate the deployment of a Camunda BPM with Amazon Web Services, using the AWS SDK for Java. 

This project is intended for development purposes only, and not for production!

Briefly, the CamundaDeploymentApplication in the project sets up a Virtual Private Cloud (VPC) in AWS, then creates an Elastic Container Service (ECS) cluster and subsequently deploys and runs the Camunda BPM as an ECS task, with AWS Fargate (serverless compute) configured, in a Docker container. 

To see information on the Camunda BPM, you can refer to:
+ [Camunda Products - The Camunda Stack](https://camunda.com/products/)

To see information on the AWS SDK for Java, you can refer to:
+ [Getting Started with the AWS SDK for Java](https://aws.amazon.com/developers/getting-started/java/?nc1=h_ls)
+ [AWS SDK for Java API Reference - 1.11.665](https://docs.aws.amazon.com/AWSJavaSDK/latest/javadoc/)
+ [AWS SDK for Java Developer Guide](https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/welcome.html)

## Requirements

+ Maven
+ Valid Amazon Web Services (AWS) developer account
+ AWS access keys (created as described on the [Security Credentials](http://aws.amazon.com/security-credentials) page and configured as described on the [Getting Started with the AWS SDK for Java](https://aws.amazon.com/developers/getting-started/java/?nc1=h_ls) page)

## Installation, Build, Run
 
+ Clone the git repository:

	git clone https://github.com/objectsource-cloud/camunda-aws.git
+ Build:

	mvn clean package
+ Run:

To deploy and start the Camunda BPM, run CamundaDeploymentApplication with the 'create' option. 

At the end of the log output, an URL will be displayed which can be used to open the Camunda Cockpit in a web browser.

Log into the Camunda Cockpit demo with demo/demo

## Undeploy
+ Undeploy / Delete:

To stop and delete the ECS and VPC configurations, run CamundaDeploymentApplication with the 'delete' option.
