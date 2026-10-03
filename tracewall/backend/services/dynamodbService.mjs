import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, PutCommand, GetCommand, UpdateCommand, DeleteCommand, QueryCommand, ScanCommand } from '@aws-sdk/lib-dynamodb';
import { config } from '../config/env.mjs';

let dynamoClient = null;
let docClient = null;

export function getDynamoClient() {
  if (!dynamoClient) {
    const clientConfig = {
      region: config.awsRegion,
    };

    if (config.awsAccessKeyId && config.awsSecretAccessKey) {
      clientConfig.credentials = {
        accessKeyId: config.awsAccessKeyId,
        secretAccessKey: config.awsSecretAccessKey,
      };
    }

    if (config.dynamodbEndpoint) {
      clientConfig.endpoint = config.dynamodbEndpoint;
    }

    dynamoClient = new DynamoDBClient(clientConfig);
    docClient = DynamoDBDocumentClient.from(dynamoClient, {
      marshallOptions: {
        removeUndefinedValues: true,
        convertClassInstanceToMap: true,
      },
      unmarshallOptions: {
        wrapNumbers: false,
      },
    });
  }
  return docClient;
}

export function getTableName() {
  return config.dynamodbTableName;
}

const PARTITION_KEY = 'IPAddress';

export async function dynamoPut(item) {
  const client = getDynamoClient();
  const command = new PutCommand({
    TableName: getTableName(),
    Item: item,
    ConditionExpression: 'attribute_not_exists(#pk)',
    ExpressionAttributeNames: {
      '#pk': PARTITION_KEY,
    },
  });
  return client.send(command);
}

export async function dynamoGet(ipAddress) {
  const client = getDynamoClient();
  const command = new GetCommand({
    TableName: getTableName(),
    Key: { [PARTITION_KEY]: ipAddress },
  });
  const result = await client.send(command);
  return result.Item || null;
}

export async function dynamoUpdate(ipAddress, updates) {
  const client = getDynamoClient();
  
  const updateExpressions = [];
  const expressionAttributeNames = {};
  const expressionAttributeValues = {};

  let paramIndex = 1;
  for (const [key, value] of Object.entries(updates)) {
    const attrName = `#attr${paramIndex}`;
    const attrValue = `:val${paramIndex}`;
    updateExpressions.push(`${attrName} = ${attrValue}`);
    expressionAttributeNames[attrName] = key;
    expressionAttributeValues[attrValue] = value;
    paramIndex++;
  }

  if (updateExpressions.length === 0) {
    return null;
  }

  updateExpressions.push('#updatedAt = :updatedAt');
  expressionAttributeNames['#updatedAt'] = 'updatedAt';
  expressionAttributeValues[':updatedAt'] = new Date().toISOString();

  const command = new UpdateCommand({
    TableName: getTableName(),
    Key: { [PARTITION_KEY]: ipAddress },
    UpdateExpression: `SET ${updateExpressions.join(', ')}`,
    ExpressionAttributeNames: {
      ...expressionAttributeNames,
      '#pk': PARTITION_KEY,
    },
    ExpressionAttributeValues: expressionAttributeValues,
    ReturnValues: 'ALL_NEW',
    ConditionExpression: 'attribute_exists(#pk)',
  });

  const result = await client.send(command);
  return result.Attributes;
}

export async function dynamoDelete(ipAddress) {
  const client = getDynamoClient();
  const command = new DeleteCommand({
    TableName: getTableName(),
    Key: { [PARTITION_KEY]: ipAddress },
    ConditionExpression: 'attribute_exists(#pk)',
    ExpressionAttributeNames: {
      '#pk': PARTITION_KEY,
    },
    ReturnValues: 'ALL_OLD',
  });
  const result = await client.send(command);
  return result.Attributes;
}

export async function dynamoQueryByIp(ipAddress) {
  const client = getDynamoClient();
  const command = new QueryCommand({
    TableName: getTableName(),
    KeyConditionExpression: '#pk = :ip',
    ExpressionAttributeNames: {
      '#pk': PARTITION_KEY,
    },
    ExpressionAttributeValues: {
      ':ip': ipAddress,
    },
  });
  const result = await client.send(command);
  return result.Items || [];
}

export async function dynamoScan(filterExpression = null, expressionAttributeValues = null, expressionAttributeNames = null) {
  const client = getDynamoClient();
  const command = new ScanCommand({
    TableName: getTableName(),
    FilterExpression: filterExpression,
    ExpressionAttributeValues: expressionAttributeValues,
    ExpressionAttributeNames: expressionAttributeNames,
  });
  const result = await client.send(command);
  return result.Items || [];
}

export function isDynamoConfigured() {
  return config.awsAccessKeyId && config.awsSecretAccessKey && config.dynamodbTableName;
}

export async function testDynamoConnection() {
  try {
    if (!isDynamoConfigured()) {
      return { status: 'NOT CONFIGURED', detail: 'AWS credentials or table name not configured' };
    }
    const client = getDynamoClient();
    const command = new ScanCommand({
      TableName: getTableName(),
      Limit: 1,
    });
    await client.send(command);
    return { status: 'CONNECTED', table: getTableName() };
  } catch (error) {
    return { status: 'ERROR', error: error.message };
  }
}