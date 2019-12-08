/*
 * Copyright (c) 2019 ObjectSource GmbH. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.objectsource.cloud.aws;

import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.amazonaws.AmazonClientException;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2ClientBuilder;
import com.amazonaws.services.ec2.model.AttachInternetGatewayRequest;
import com.amazonaws.services.ec2.model.AttachInternetGatewayResult;
import com.amazonaws.services.ec2.model.AuthorizeSecurityGroupIngressRequest;
import com.amazonaws.services.ec2.model.AuthorizeSecurityGroupIngressResult;
import com.amazonaws.services.ec2.model.CreateInternetGatewayRequest;
import com.amazonaws.services.ec2.model.CreateInternetGatewayResult;
import com.amazonaws.services.ec2.model.CreateRouteRequest;
import com.amazonaws.services.ec2.model.CreateRouteResult;
import com.amazonaws.services.ec2.model.CreateSecurityGroupRequest;
import com.amazonaws.services.ec2.model.CreateSecurityGroupResult;
import com.amazonaws.services.ec2.model.CreateSubnetRequest;
import com.amazonaws.services.ec2.model.CreateSubnetResult;
import com.amazonaws.services.ec2.model.CreateVpcRequest;
import com.amazonaws.services.ec2.model.CreateVpcResult;
import com.amazonaws.services.ec2.model.DeleteInternetGatewayRequest;
import com.amazonaws.services.ec2.model.DeleteInternetGatewayResult;
import com.amazonaws.services.ec2.model.DeleteRouteRequest;
import com.amazonaws.services.ec2.model.DeleteRouteResult;
import com.amazonaws.services.ec2.model.DeleteSecurityGroupRequest;
import com.amazonaws.services.ec2.model.DeleteSecurityGroupResult;
import com.amazonaws.services.ec2.model.DeleteSubnetRequest;
import com.amazonaws.services.ec2.model.DeleteSubnetResult;
import com.amazonaws.services.ec2.model.DeleteVpcRequest;
import com.amazonaws.services.ec2.model.DeleteVpcResult;
import com.amazonaws.services.ec2.model.DescribeInternetGatewaysRequest;
import com.amazonaws.services.ec2.model.DescribeInternetGatewaysResult;
import com.amazonaws.services.ec2.model.DescribeNetworkInterfacesRequest;
import com.amazonaws.services.ec2.model.DescribeNetworkInterfacesResult;
import com.amazonaws.services.ec2.model.DescribeRouteTablesRequest;
import com.amazonaws.services.ec2.model.DescribeRouteTablesResult;
import com.amazonaws.services.ec2.model.DescribeSecurityGroupsRequest;
import com.amazonaws.services.ec2.model.DescribeSecurityGroupsResult;
import com.amazonaws.services.ec2.model.DescribeSubnetsRequest;
import com.amazonaws.services.ec2.model.DescribeSubnetsResult;
import com.amazonaws.services.ec2.model.DescribeVpcsRequest;
import com.amazonaws.services.ec2.model.DescribeVpcsResult;
import com.amazonaws.services.ec2.model.DetachInternetGatewayRequest;
import com.amazonaws.services.ec2.model.DetachInternetGatewayResult;
import com.amazonaws.services.ec2.model.Filter;
import com.amazonaws.services.ec2.model.InternetGateway;
import com.amazonaws.services.ec2.model.IpPermission;
import com.amazonaws.services.ec2.model.IpRange;
import com.amazonaws.services.ec2.model.NetworkInterface;
import com.amazonaws.services.ec2.model.SecurityGroup;
import com.amazonaws.services.ec2.model.Subnet;
import com.amazonaws.services.ec2.model.Tag;
import com.amazonaws.services.ec2.model.Vpc;
import com.amazonaws.services.ecs.AmazonECS;
import com.amazonaws.services.ecs.AmazonECSClientBuilder;
import com.amazonaws.services.ecs.model.AssignPublicIp;
import com.amazonaws.services.ecs.model.Attachment;
import com.amazonaws.services.ecs.model.AwsVpcConfiguration;
import com.amazonaws.services.ecs.model.Cluster;
import com.amazonaws.services.ecs.model.ContainerDefinition;
import com.amazonaws.services.ecs.model.CreateClusterRequest;
import com.amazonaws.services.ecs.model.CreateClusterResult;
import com.amazonaws.services.ecs.model.DeleteClusterRequest;
import com.amazonaws.services.ecs.model.DeleteClusterResult;
import com.amazonaws.services.ecs.model.DeregisterTaskDefinitionRequest;
import com.amazonaws.services.ecs.model.DeregisterTaskDefinitionResult;
import com.amazonaws.services.ecs.model.DescribeClustersRequest;
import com.amazonaws.services.ecs.model.DescribeClustersResult;
import com.amazonaws.services.ecs.model.DescribeTasksRequest;
import com.amazonaws.services.ecs.model.KeyValuePair;
import com.amazonaws.services.ecs.model.LaunchType;
import com.amazonaws.services.ecs.model.ListClustersRequest;
import com.amazonaws.services.ecs.model.ListClustersResult;
import com.amazonaws.services.ecs.model.ListTaskDefinitionsRequest;
import com.amazonaws.services.ecs.model.ListTaskDefinitionsResult;
import com.amazonaws.services.ecs.model.ListTasksRequest;
import com.amazonaws.services.ecs.model.ListTasksResult;
import com.amazonaws.services.ecs.model.NetworkConfiguration;
import com.amazonaws.services.ecs.model.NetworkMode;
import com.amazonaws.services.ecs.model.PortMapping;
import com.amazonaws.services.ecs.model.RegisterTaskDefinitionRequest;
import com.amazonaws.services.ecs.model.RegisterTaskDefinitionResult;
import com.amazonaws.services.ecs.model.RunTaskRequest;
import com.amazonaws.services.ecs.model.RunTaskResult;
import com.amazonaws.services.ecs.model.StopTaskRequest;
import com.amazonaws.services.ecs.model.StopTaskResult;
import com.amazonaws.services.ecs.model.Task;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagement;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClientBuilder;
import com.amazonaws.services.identitymanagement.model.GetRoleRequest;
import com.amazonaws.services.identitymanagement.model.Role;
import com.amazonaws.services.rds.AmazonRDS;
import com.amazonaws.services.rds.AmazonRDSClientBuilder;
import com.amazonaws.services.rds.model.CreateDBInstanceRequest;
import com.amazonaws.services.rds.model.DBInstance;
import com.amazonaws.services.rds.model.DeleteDBInstanceRequest;
import com.amazonaws.services.rds.model.DescribeDBInstancesRequest;
import com.amazonaws.services.rds.model.DescribeDBInstancesResult;
import com.amazonaws.waiters.WaiterParameters;

public class CamundaDeploymentApplication {

    private static final String ACTION_CREATE = "create";

    private static final String ACTION_CREATE_DB = "create_db";

    private static final String ACTION_DELETE = "delete";

    private static final String ACTION_DELETE_DB = "delete_db";

    private static final String CONTAINER_NAME = "camunda_bpm_platform";

    private static final Logger LOG = LoggerFactory.getLogger(CamundaDeploymentApplication.class);

    private static final String DB_INSTANCE_IDENTIFIER = "processenginedemo";

    private static final String CLUSTER_NAME = "camunda";

    private static final String TASK_DEFINITION_FAMILY = "camunda";

    private static final String SECURITY_GROUP = "camunda-sg";

    public static void main(String[] args) {
        Region region = Region.getRegion(Regions.EU_CENTRAL_1);

        try {
            String action = args.length > 0 ? args[0] : null;
            if (ACTION_CREATE.equalsIgnoreCase(action)) {
                createVpc(region);
                createTaskDefinition(region, null);
                createCluster(region);
                runTask(region);
            } else if (ACTION_CREATE_DB.equalsIgnoreCase(action)) {
                DBInstance dbInstance = findDBInstance(region, DB_INSTANCE_IDENTIFIER);
                if (dbInstance == null) {
                    dbInstance = createDatabase(region);
                }
            } else if (ACTION_DELETE.equalsIgnoreCase(action)) {
                stopClusterTasks(region);
                deleteCluster(region);
                deleteTaskDefinition(region);
                deleteVpc(region);
            } else if (ACTION_DELETE_DB.equalsIgnoreCase(action)) {
                deleteDatabase(region);
            } else {
                LOG.error("No action (create|delete) specified!");
            }
        } catch (AmazonServiceException ase) {
            LOG.error("Amazon service error");
            LOG.error(String.format("Error Message:    %s", ase.getMessage()));
            LOG.error(String.format("HTTP Status Code: %s", ase.getStatusCode()));
            LOG.error(String.format("AWS Error Code:   %s", ase.getErrorCode()));
            LOG.error(String.format("Error Type:       %s", ase.getErrorType()));
            LOG.error(String.format("Request ID:       %s", ase.getRequestId()));
        } catch (AmazonClientException ace) {
            LOG.error("Amazon client error", ace);
        }

    }

    /**
     * Creates a PostgreSQL database with AWS RDS for the Camunda BPM.
     * 
     * @param region region in which to create the database.
     * @return {@link DBInstance} describing the database.
     */
    private static DBInstance createDatabase(Region region) {
        AmazonRDS rds = AmazonRDSClientBuilder.standard().withRegion(region.getName()).build();

        String dbInstanceIdentifier = DB_INSTANCE_IDENTIFIER;

        LOG.info("Creating PostgreSQL database...");

        CreateDBInstanceRequest req = new CreateDBInstanceRequest();
        req.setEngine("postgres");
        req.setEngineVersion("9.3");
        req.setDBInstanceClass("db.t2.micro");
        req.setMultiAZ(false);
        req.setStorageType("standard");
        req.setAllocatedStorage(5);
        req.setDBInstanceIdentifier(dbInstanceIdentifier);
        req.setMasterUsername("camunda");
        req.setMasterUserPassword("nobullshitbpm");
        DBInstance dbInstance = rds.createDBInstance(req);

        if (LOG.isInfoEnabled()) {
            LOG.info(String.format("Database %s created.", dbInstance.getDBInstanceIdentifier()));
            LOG.info(String.format("Database Resource-ID: %s", dbInstance.getDbiResourceId()));
        }

        LOG.info("Waiting until database is available...");

        DescribeDBInstancesRequest r = new DescribeDBInstancesRequest().withDBInstanceIdentifier(dbInstanceIdentifier);
        rds.waiters().dBInstanceAvailable().run(new WaiterParameters<DescribeDBInstancesRequest>(r));

        if (LOG.isInfoEnabled()) {
            LOG.info(String.format("Database %s available.", dbInstance.getDBInstanceIdentifier()));
        }

        return findDBInstance(region, dbInstanceIdentifier);
    }

    /**
     * Finds the AWS RDS database instance with the specified identifier in the
     * specified AWS region.
     * 
     * @param region               region in which the database instance is located.
     * @param dbInstanceIdentifier database instance identifier.
     * @return {@link DBInstance} describing the database matching the identifier,
     *         otherwise <code>null</code>.
     */
    private static DBInstance findDBInstance(Region region, String dbInstanceIdentifier) {
        AmazonRDS rds = AmazonRDSClientBuilder.standard().withRegion(region.getName()).build();

        DescribeDBInstancesResult ddbiRes = rds.describeDBInstances();
        for (DBInstance dbi : ddbiRes.getDBInstances()) {
            if (dbInstanceIdentifier.equals(dbi.getDBInstanceIdentifier())) {
                return dbi;
            }
        }
        return null;
    }

    /**
     * Deletes the AWS RDS database instance used by the Camunda BPM, as part of the
     * &apos;delete&apos; option
     * 
     * @param region region in which the database instance is located.
     * @return {@link DBInstance} describing the database.
     */
    private static DBInstance deleteDatabase(Region region) {
        AmazonRDS rds = AmazonRDSClientBuilder.standard().withRegion(region.getName()).build();

        String dbInstanceIdentifier = DB_INSTANCE_IDENTIFIER;

        LOG.info("Deleting database...");

        DeleteDBInstanceRequest req = new DeleteDBInstanceRequest();
        req.setDBInstanceIdentifier(dbInstanceIdentifier);
        req.setSkipFinalSnapshot(true);

        DBInstance dbInstance = rds.deleteDBInstance(req);

        if (LOG.isInfoEnabled()) {
            LOG.info(String.format("Database deletion of %s started.", dbInstance.getDBInstanceIdentifier()));
        }

        LOG.info("Waiting until database is deleted...");

        DescribeDBInstancesRequest r = new DescribeDBInstancesRequest();
        r.setDBInstanceIdentifier(dbInstanceIdentifier);
        rds.waiters().dBInstanceDeleted().run(new WaiterParameters<DescribeDBInstancesRequest>(r));

        if (LOG.isInfoEnabled()) {
            LOG.info(String.format("Database %s deleted.", dbInstance.getDBInstanceIdentifier()));
        }

        return findDBInstance(region, dbInstanceIdentifier);
    }

    /**
     * Finds a AWS VPC with the specified CIDR.
     * 
     * @param ec2  {@link AmazonEC2}
     * @param cidr CIDR
     * @return {@link Vpc} describing the VPC with the specified CIDR, otherwise
     *         <code>null</code>.
     */
    private static Vpc findVpcByCidr(AmazonEC2 ec2, String cidr) {
        DescribeVpcsRequest vReq = new DescribeVpcsRequest()
                .withFilters(new Filter().withName("cidr").withValues(cidr));
        DescribeVpcsResult vRes = ec2.describeVpcs(vReq);
        return vRes.getVpcs().stream().findFirst().orElse(null);
    }

    /**
     * Finds the value of the specified ECS task&aposs detail entry with the
     * specified name.
     * 
     * @param task       ECS task
     * @param detailName detail entry name
     * @return value of the detail entry.
     */
    private static String findTaskDetailValue(Task task, String detailName) {
        for (Attachment a : task.getAttachments()) {
            for (KeyValuePair kv : a.getDetails()) {
                if (detailName.equals(kv.getName())) {
                    return kv.getValue();
                }
            }
        }
        return null;
    }

    /**
     * Finds the network interfaces attached to the specified ECS task.
     * 
     * @param ec2  {@link AmazonEC2}
     * @param task ECS task
     * @return List of {@link NetworkInterface}
     */
    private static List<NetworkInterface> findNetworkInterfaces(AmazonEC2 ec2, Task task) {
        String networkInterfaceId = findTaskDetailValue(task, "networkInterfaceId");
        DescribeNetworkInterfacesRequest dniReq = new DescribeNetworkInterfacesRequest()
                .withNetworkInterfaceIds(networkInterfaceId);
        DescribeNetworkInterfacesResult dniRes = ec2.describeNetworkInterfaces(dniReq);
        return dniRes.getNetworkInterfaces();
    }

    /**
     * Finds the public IP address under which the running ECS task is accessible.
     * 
     * @param ecs  {@link AmazonECS}
     * @param ec2  {@link AmazonEC2}
     * @param task ECS task
     * @return public IP address when this has been enabled, otherwise
     *         <code>null</code>
     */
    private static String findPublicIp(AmazonECS ecs, AmazonEC2 ec2, Task task) {
        for (NetworkInterface ni : findNetworkInterfaces(ec2, task)) {
            return ni.getAssociation().getPublicIp();
        }
        return null;
    }

    /**
     * Finds the first AWS Internet gateway attached to the AWS VPC with the
     * specified ID.
     * 
     * @param ec2   {@link AmazonEC2}
     * @param vpcId VPC-ID
     * @return {@link InternetGateway} describing the first attached Internet
     *         gateway, otherwise <code>null</code>
     */
    private static InternetGateway findInternetGatewayByVpcId(AmazonEC2 ec2, String vpcId) {
        DescribeInternetGatewaysRequest digwReq = new DescribeInternetGatewaysRequest()
                .withFilters(new Filter().withName("attachment.vpc-id").withValues(vpcId));
        DescribeInternetGatewaysResult digwRes = ec2.describeInternetGateways(digwReq);
        return digwRes.getInternetGateways().stream().findFirst().orElse(null);
    }

    /**
     * Find the VPC subnet with the specified CIDR.
     * 
     * @param ec2  {@link AmazonEC2}
     * @param cidr CIDR
     * @return {@link Subnet}
     */
    private static Subnet findSubnetByCidr(AmazonEC2 ec2, String cidr) {
        DescribeSubnetsRequest sReq = new DescribeSubnetsRequest()
                .withFilters(new Filter().withName("cidr").withValues(cidr));
        DescribeSubnetsResult sRes = ec2.describeSubnets(sReq);
        return sRes.getSubnets().stream().findFirst().orElse(null);
    }

    /**
     * Find a security group using the specified VPC-ID and group name.
     * 
     * @param ec2       {@link AmazonEC2}
     * @param vpcId     VPC-ID
     * @param groupName security group name
     * @return {@link SecurityGroup}
     */
    private static SecurityGroup findSecurityGroup(AmazonEC2 ec2, String vpcId, String groupName) {
        DescribeSecurityGroupsRequest sgReq = new DescribeSecurityGroupsRequest().withFilters(
                new Filter().withName("vpc-id").withValues(vpcId),
                new Filter().withName("group-name").withValues(groupName));
        DescribeSecurityGroupsResult sgRes = ec2.describeSecurityGroups(sgReq);
        return sgRes.getSecurityGroups().stream().findFirst().orElse(null);
    }

    /**
     * Creates the AWS VPC, and other associated network infrastructure such as
     * subnet and Internet gateway, for the deployment of the Camunda BPM in the
     * specified AWS region.
     * 
     * @param region AWS region
     */
    private static void createVpc(Region region) {
        AmazonEC2 ec2 = AmazonEC2ClientBuilder.standard().withRegion(region.getName()).build();

        LOG.info("Creating VPC...");

        CreateVpcRequest vpcReq = new CreateVpcRequest().withCidrBlock("155.2.0.0/16");
        CreateVpcResult vpcRes = ec2.createVpc(vpcReq);
        String vpcId = vpcRes.getVpc().getVpcId();
        vpcRes.getVpc().withTags(new Tag("name", "camunda-vpc"));

        LOG.info("Creating subnet...");

        CreateSubnetRequest snReq = new CreateSubnetRequest().withCidrBlock("155.2.1.0/24").withVpcId(vpcId);
        CreateSubnetResult snRes = ec2.createSubnet(snReq);
        if (LOG.isInfoEnabled()) {
            LOG.info(String.format("Create subnet response %s", snRes.getSdkResponseMetadata()));
        }

        LOG.info("Creating IGW...");

        CreateInternetGatewayRequest igwReq = new CreateInternetGatewayRequest();
        CreateInternetGatewayResult igwRes = ec2.createInternetGateway(igwReq);
        String internetGatewayId = igwRes.getInternetGateway().getInternetGatewayId();

        LOG.info("Attaching IGW to VPC ...");

        AttachInternetGatewayRequest aigwReq = new AttachInternetGatewayRequest().withVpcId(vpcId)
                .withInternetGatewayId(internetGatewayId);
        AttachInternetGatewayResult aigwRes = ec2.attachInternetGateway(aigwReq);
        if (LOG.isInfoEnabled()) {
            LOG.info(String.format("Attach internal gateway response %s", aigwRes.getSdkResponseMetadata()));
        }

        LOG.info("Getting main route table...");

        DescribeRouteTablesRequest drtReq = new DescribeRouteTablesRequest();
        Filter f = new Filter().withName("vpc-id").withValues(vpcId);
        Filter f2 = new Filter().withName("association.main").withValues("true");
        drtReq.setFilters(Arrays.asList(f, f2));
        DescribeRouteTablesResult drtRes = ec2.describeRouteTables(drtReq);
        String routeTableId = drtRes.getRouteTables().get(0).getRouteTableId();

        LOG.info("Creating IGW route...");

        CreateRouteRequest rReq = new CreateRouteRequest().withDestinationCidrBlock("0.0.0.0/0")
                .withRouteTableId(routeTableId).withGatewayId(internetGatewayId);
        CreateRouteResult rRes2 = ec2.createRoute(rReq);
        if (LOG.isInfoEnabled()) {
            LOG.info(String.format("Create IGW route response %s", rRes2.getSdkResponseMetadata()));
        }

        LOG.info("Creating security group...");

        CreateSecurityGroupRequest sgReq = new CreateSecurityGroupRequest().withGroupName(SECURITY_GROUP)
                .withDescription("Security group for camunda").withVpcId(vpcId);
        CreateSecurityGroupResult sgRes = ec2.createSecurityGroup(sgReq);
        if (LOG.isInfoEnabled()) {
            LOG.info(String.format("Create security group response %s", sgRes.getSdkResponseMetadata()));
        }
        String groupId = sgRes.getGroupId();

        IpPermission ipPerm = new IpPermission().withIpProtocol("tcp").withToPort(8080).withFromPort(8080)
                .withIpv4Ranges(new IpRange().withCidrIp("0.0.0.0/0"));

        AuthorizeSecurityGroupIngressRequest asgiReq = new AuthorizeSecurityGroupIngressRequest().withGroupId(groupId)
                .withIpPermissions(ipPerm);
        AuthorizeSecurityGroupIngressResult asgiRes = ec2.authorizeSecurityGroupIngress(asgiReq);
        if (LOG.isInfoEnabled()) {
            LOG.info(String.format("Authorize security group ingress response %s", asgiRes.getSdkResponseMetadata()));
        }
    }

    /**
     * Removes the previously created AWS VPC, and other associated network
     * infrastructure, as part of the 'delete' option.
     * 
     * @param region AWS region
     */
    private static void deleteVpc(Region region) {
        AmazonEC2 ec2 = AmazonEC2ClientBuilder.standard().withRegion(region.getName()).build();
        String cidr = "155.2.0.0/16";

        Vpc vpc = findVpcByCidr(ec2, cidr);
        if (vpc == null) {
            if (LOG.isInfoEnabled()) {
                LOG.info(String.format("VPC with CIDR %s not found!", cidr));
            }
            return;
        }

        String vpcId = vpc.getVpcId();

        LOG.info("Deleting security group...");

        SecurityGroup sg = findSecurityGroup(ec2, vpcId, SECURITY_GROUP);
        if (sg != null) {
            DeleteSecurityGroupRequest sgReq = new DeleteSecurityGroupRequest().withGroupId(sg.getGroupId());
            DeleteSecurityGroupResult sgRes = ec2.deleteSecurityGroup(sgReq);
            if (LOG.isInfoEnabled()) {
                LOG.info(String.format("Delete security group response %s", sgRes.getSdkResponseMetadata()));
            }
        }

        LOG.info("Getting main route table...");

        String routeTableId = findRouteTableByVpcId(ec2, vpcId);
        if (routeTableId != null) {
            LOG.info("Deleting IGW route...");

            DeleteRouteRequest rReq = new DeleteRouteRequest().withDestinationCidrBlock("0.0.0.0/0")
                    .withRouteTableId(routeTableId);
            DeleteRouteResult rRes = ec2.deleteRoute(rReq);
            if (LOG.isInfoEnabled()) {
                LOG.info(String.format("Delete IGW route response %s", rRes.getSdkResponseMetadata()));
            }
        }

        InternetGateway igw = findInternetGatewayByVpcId(ec2, vpcId);
        if (igw != null) {
            LOG.info("Detaching IGW to VPC ...");

            DetachInternetGatewayRequest digwReq = new DetachInternetGatewayRequest().withVpcId(vpcId)
                    .withInternetGatewayId(igw.getInternetGatewayId());
            DetachInternetGatewayResult aigwRes = ec2.detachInternetGateway(digwReq);
            if (LOG.isInfoEnabled()) {
                LOG.info(String.format("Detach IGW response %s", aigwRes.getSdkResponseMetadata()));
            }

            LOG.info("Deleting IGW...");

            DeleteInternetGatewayRequest igwReq = new DeleteInternetGatewayRequest()
                    .withInternetGatewayId(igw.getInternetGatewayId());
            DeleteInternetGatewayResult igwRes = ec2.deleteInternetGateway(igwReq);
            if (LOG.isInfoEnabled()) {
                LOG.info(String.format("Delete IGW response %s", igwRes.getSdkResponseMetadata()));
            }
        }

        deleteSubnet(ec2, "155.2.0.0/16");
        deleteSubnet(ec2, "155.2.1.0/24");

        LOG.info("Deleting VPC...");

        DeleteVpcRequest vpcReq = new DeleteVpcRequest().withVpcId(vpcId);
        DeleteVpcResult vpcRes = ec2.deleteVpc(vpcReq);
        if (LOG.isInfoEnabled()) {
            LOG.info(String.format("Delete VPC response %s", vpcRes.getSdkResponseMetadata()));
        }
    }

    /**
     * Deletes the AWS subnet with the specified CIDR.
     * 
     * @param ec2        {@link AmazonEC2}
     * @param subnetCidr CIDR
     */
    private static void deleteSubnet(AmazonEC2 ec2, String subnetCidr) {
        Subnet subnet = findSubnetByCidr(ec2, subnetCidr);
        if (subnet != null) {
            LOG.info("Deleting subnet...");

            DeleteSubnetRequest snReq = new DeleteSubnetRequest().withSubnetId(subnet.getSubnetId());
            DeleteSubnetResult snRes = ec2.deleteSubnet(snReq);
            if (LOG.isInfoEnabled()) {
                LOG.info(String.format("Delete subnet response %s", snRes.getSdkResponseMetadata()));
            }
        }
    }

    /**
     * Finds the first route table attached to the VPC with the specified VPC-ID
     * 
     * @param ec2   {@link AmazonEC2}
     * @param vpcId VPC-ID
     * @return ID of the route table
     */
    private static String findRouteTableByVpcId(AmazonEC2 ec2, String vpcId) {
        DescribeRouteTablesRequest drtReq = new DescribeRouteTablesRequest();
        Filter f = new Filter().withName("vpc-id").withValues(vpcId);
        Filter f2 = new Filter().withName("association.main").withValues("true");
        drtReq.setFilters(Arrays.asList(f, f2));
        DescribeRouteTablesResult drtRes = ec2.describeRouteTables(drtReq);
        return drtRes.getRouteTables().get(0).getRouteTableId();
    }

    /**
     * Creates an ECS cluster for the deployment of the Camunda BPM.
     * 
     * @param region AWS region in which to create the cluster
     * @return {@link CreateClusterResult}
     */
    private static CreateClusterResult createCluster(Region region) {
        AmazonEC2 ec2 = AmazonEC2ClientBuilder.standard().withRegion(region.getName()).build();
        AmazonECS ecs = AmazonECSClientBuilder.standard().withRegion(region.getName()).build();

        return createCluster(ec2, ecs);
    }

    /**
     * Creates an ECS cluster for the deployment of the Camunda BPM.
     * 
     * @param ec2 {@link AmazonEC2}
     * @param ecs {@link AmazonECS}
     * @return {@link CreateClusterResult}
     */
    private static CreateClusterResult createCluster(AmazonEC2 ec2, AmazonECS ecs) {
        LOG.info("Creating cluster...");

        CreateClusterRequest cReq = new CreateClusterRequest();
        cReq.setClusterName(CLUSTER_NAME);
        CreateClusterResult cRes = ecs.createCluster(cReq);
        if (LOG.isInfoEnabled()) {
            LOG.info("Create cluster " + cRes.getCluster());
        }

        return cRes;
    }

    /**
     * Runs an ECS task with the Camunda BPM in a Docker container.
     * 
     * @param region AWS region
     */
    private static void runTask(Region region) {
        AmazonEC2 ec2 = AmazonEC2ClientBuilder.standard().withRegion(region.getName()).build();
        AmazonECS ecs = AmazonECSClientBuilder.standard().withRegion(region.getName()).build();

        runTask(ec2, ecs);
    }

    /**
     * Runs an ECS task with the Camunda BPM in a Docker container.
     * 
     * @param ec2 {@link AmazonEC2}
     * @param ecs {@link AmazonECS}
     */
    private static void runTask(AmazonEC2 ec2, AmazonECS ecs) {
        LOG.info("Running task...");

        Vpc vpc = findVpcByCidr(ec2, "155.2.0.0/16");
        Subnet subnet = findSubnetByCidr(ec2, "155.2.1.0/24");
        SecurityGroup securityGroup = findSecurityGroup(ec2, vpc.getVpcId(), SECURITY_GROUP);

        AwsVpcConfiguration vc = new AwsVpcConfiguration().withAssignPublicIp(AssignPublicIp.ENABLED)
                .withSecurityGroups(securityGroup.getGroupId()).withSubnets(subnet.getSubnetId());
        NetworkConfiguration nc = new NetworkConfiguration().withAwsvpcConfiguration(vc);
        RunTaskRequest rtReq = new RunTaskRequest().withCluster(CLUSTER_NAME).withCount(1)
                .withLaunchType(LaunchType.FARGATE).withNetworkConfiguration(nc).withStartedBy("SDK")
                .withTaskDefinition(TASK_DEFINITION_FAMILY);
        RunTaskResult rtRes = ecs.runTask(rtReq);
        Task t = rtRes.getTasks().get(0);
        String taskArn = t.getTaskArn();

        if (LOG.isInfoEnabled()) {
            LOG.info(String.format("Waiting until task %s is running...", taskArn));
        }

        DescribeTasksRequest r = new DescribeTasksRequest().withCluster(CLUSTER_NAME).withTasks(taskArn);
        ecs.waiters().tasksRunning().run(new WaiterParameters<DescribeTasksRequest>(r));

        if (LOG.isInfoEnabled()) {
            LOG.info(String.format("Task %s is runuing.", taskArn));
        }

        if (LOG.isInfoEnabled()) {
            String publicIp = findPublicIp(ecs, ec2, t);
            LOG.info(String.format(
                    "Access the Camunda Cockpit with the following URL: \nhttp://%s:8080/camunda/app/cockpit/default/#/login",
                    publicIp));
        }
    }

    /**
     * Deletes the Camunda ECS Cluster, as part of the 'delete' option.
     * 
     * @param region AWS region
     * @return {@link DeleteClusterResult}
     */
    private static DeleteClusterResult deleteCluster(Region region) {
        AmazonECS ecs = AmazonECSClientBuilder.standard().withRegion(region.getName()).build();
        return deleteCluster(ecs);
    }

    private static DeleteClusterResult deleteCluster(AmazonECS ecs) {
        LOG.info("Deleting cluster...");

        DeleteClusterRequest dcReq = new DeleteClusterRequest().withCluster(CLUSTER_NAME);
        DeleteClusterResult dcRes = ecs.deleteCluster(dcReq);

        if (LOG.isInfoEnabled()) {
            LOG.info("Deleted cluster " + dcRes.getCluster());
        }

        return dcRes;
    }

    private static void stopClusterTasks(Region region) {
        AmazonECS ecs = AmazonECSClientBuilder.standard().withRegion(region.getName()).build();
        stopClusterTasks(ecs);
    }

    private static Cluster findCluster(AmazonECS ecs, String clusterName) {
        ListClustersRequest lcReq = new ListClustersRequest();
        ListClustersResult lcRes = ecs.listClusters(lcReq);
        DescribeClustersRequest dcReq = new DescribeClustersRequest().withClusters(lcRes.getClusterArns());
        DescribeClustersResult dcRes = ecs.describeClusters(dcReq);
        for (Cluster c : dcRes.getClusters()) {
            if (clusterName.equals(c.getClusterName())) {
                return c;
            }
        }
        return null;
    }

    /**
     * Stops all tasks in the Camunda ECS cluster.
     * 
     * @param ecs {@link AmazonECS}
     */
    private static void stopClusterTasks(AmazonECS ecs) {
        LOG.info("Stopping tasks...");

        Cluster c = findCluster(ecs, CLUSTER_NAME);
        if (c != null) {
            ListTasksRequest ltReq = new ListTasksRequest().withCluster(c.getClusterArn());
            ListTasksResult ltRes = ecs.listTasks(ltReq);
            for (String tArn : ltRes.getTaskArns()) {
                StopTaskRequest stReq = new StopTaskRequest().withTask(tArn).withCluster(c.getClusterArn());
                StopTaskResult stRes = ecs.stopTask(stReq);
                Task t = stRes.getTask();
                if (LOG.isInfoEnabled()) {
                    LOG.info(String.format("Stopping task %s", t));
                }

                if (LOG.isInfoEnabled()) {
                    LOG.info(String.format("Waiting until task %s to stop...", tArn));
                }

                DescribeTasksRequest r = new DescribeTasksRequest().withTasks(tArn).withCluster(c.getClusterArn());
                ecs.waiters().tasksStopped().run(new WaiterParameters<DescribeTasksRequest>(r));

                if (LOG.isInfoEnabled()) {
                    LOG.info(String.format("Stopped task %s.", tArn));
                }
            }
        }
    }

    /**
     * Creates / registers the ECS task definition which defines the Camunda BPM
     * container.
     * 
     * @param region     AWS region
     * @param dbInstance optional {@link DBInstance}
     * @return {@link RegisterTaskDefinitionResult}
     */
    private static RegisterTaskDefinitionResult createTaskDefinition(Region region, DBInstance dbInstance) {
        AmazonECS ecs = AmazonECSClientBuilder.standard().withRegion(region.getName()).build();
        AmazonIdentityManagement im = AmazonIdentityManagementClientBuilder.standard().withRegion(region.getName())
                .build();
        return createTaskDefinition(ecs, im, dbInstance);
    }

    /**
     * Creates / registers the ECS task definition which defines the Camunda BPM
     * container.
     * 
     * @param ecs        {@link AmazonECS}
     * @param im         {@link AmazonIdentityManagement}
     * @param dbInstance optional {@link DBInstance}
     * @return {@link RegisterTaskDefinitionResult}
     */
    private static RegisterTaskDefinitionResult createTaskDefinition(AmazonECS ecs, AmazonIdentityManagement im,
            DBInstance dbInstance) {
        LOG.info("Creating task definition...");

        ContainerDefinition camundaContainerDef = new ContainerDefinition().withName(CONTAINER_NAME)
                .withImage("camunda/camunda-bpm-platform:latest").withCpu(512).withMemory(1024)
                .withPortMappings(Arrays.asList(new PortMapping().withHostPort(8080).withContainerPort(8080)))
                .withEssential(true);

        if (dbInstance != null) {
            camundaContainerDef.withEnvironment(Arrays.asList(newKeyValuePair("DB_DRIVER", "org.postgresql.Driver"),
                    newKeyValuePair("DB_USERNAME", "camunda"), newKeyValuePair("DB_PASSWORD", "nobullshitbpm"),
                    newKeyValuePair("DB_URL", "jdbc:postgresql://" + dbInstance.getEndpoint().getAddress())));
        }

        RegisterTaskDefinitionRequest rtdReq = new RegisterTaskDefinitionRequest().withFamily(TASK_DEFINITION_FAMILY)
                .withContainerDefinitions(Arrays.asList(camundaContainerDef)).withNetworkMode(NetworkMode.Awsvpc)
                .withCpu("512").withMemory("1024").withTaskRoleArn(findRole(im, "ecsTaskExecutionRole").getArn())
                .withRequiresCompatibilities(Arrays.asList("FARGATE"));

        RegisterTaskDefinitionResult rtdRes = ecs.registerTaskDefinition(rtdReq);

        if (LOG.isInfoEnabled()) {
            LOG.info(String.format("Created task definition %s", rtdRes.getTaskDefinition()));
        }

        return rtdRes;
    }

    /**
     * Deletes / deregisters the ECS task definition which defines the Camunda BPM
     * container. container.
     * 
     * @param region AWS region
     */
    private static void deleteTaskDefinition(Region region) {
        LOG.info("Deregistering task definitions...");

        AmazonECS ecs = AmazonECSClientBuilder.standard().withRegion(region.getName()).build();
        ListTaskDefinitionsRequest ltdReq = new ListTaskDefinitionsRequest().withFamilyPrefix(TASK_DEFINITION_FAMILY);
        ListTaskDefinitionsResult ltdRes = ecs.listTaskDefinitions(ltdReq);
        for (String td : ltdRes.getTaskDefinitionArns()) {
            DeregisterTaskDefinitionRequest dtdReq = new DeregisterTaskDefinitionRequest().withTaskDefinition(td);
            DeregisterTaskDefinitionResult dtdRes = ecs.deregisterTaskDefinition(dtdReq);
            if (LOG.isInfoEnabled()) {
                LOG.info(String.format("Deregister task definition %s with response %s", dtdRes.getTaskDefinition(),
                        dtdRes.getSdkResponseMetadata()));
            }
        }
    }

    private static Role findRole(AmazonIdentityManagement im, String role) {
        return im.getRole(new GetRoleRequest().withRoleName(role)).getRole();
    }

    private static KeyValuePair newKeyValuePair(String name, String value) {
        return new KeyValuePair().withName(name).withValue(value);
    }
}
