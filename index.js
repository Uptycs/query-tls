'use strict';

const crypto = require('crypto');
const fs = require('fs');
const re = require('json-logic-js');
const AWS = require('aws-sdk');

const ENROLL_SECRET = process.env.ENROLL_SECRET || '';
const Bucket = process.env.S3_BUCKET;
const ContentType = 'application/json';
const TopicArn = process.env.SNC_TOPIC_ARN;

const OK = {statusCode: 200};
const ERROR = {statusCode: 500};
const NODE_KEY = crypto.createHash('sha256').update(ENROLL_SECRET).digest('hex');
const RULES = getRules();

const s3 = new AWS.S3({region: process.env.AWS_REGION});
const sns = new AWS.SNS({region: process.env.AWS_REGION});

async function handler(event) {
  if (event.path !== '/enroll' && event.path !== '/log') {
    console.error('Invalid URL:', event.path);
    return ERROR;
  }
  if (!event.body) {
    console.error('Invalid request body:', event.body);
    return ERROR;
  }

  let body;
  try {
    body = JSON.parse(event.body);
  } catch (err) {
    console.error('Request body is not JSON:', event.body);
    return ERROR;
  }

  if (event.path === '/enroll') {
    return enroll(body);
  }

  return await log(body);
}

function getRules() {
  const rules = {};
  for (const ruleFile of fs.readdirSync(__dirname + '/rules')) {
    // { group_name: { tables: [ ... ], rules: { rule_name: { ... }, ... } }, ... }
    const parsed = JSON.parse(fs.readFileSync(__dirname + '/rules/' + ruleFile));

    // Re-arrange rules by tables: { table: { rule_name: { ... }, ... }, ... }
    Object.keys(parsed).forEach(groupName => {
      const group = parsed[groupName];
      for (const tableName of group.tables) {
        const tableRules = rules[tableName] || {};
        rules[tableName] = tableRules;
        Object.keys(group.rules).forEach(ruleName => tableRules[ruleName] = group.rules[ruleName]);
      }
    });
  }

  return rules;
}

function enroll(body) {
  if (body.enroll_secret !== ENROLL_SECRET) {
    console.error('Invalid enroll secret');
    return ERROR;
  }
  return {statusCode: 200, body: JSON.stringify({node_key: NODE_KEY, node_invalid: false})};
}

async function log(body) {
  if (body.node_key !== NODE_KEY) {
    console.error('Invalid node key:', body.node_key);
    return ERROR;
  }

  let data;
  if (body.log_type === 'status') {
    logStatus(body.data);
    return OK;
  } else if (body.log_type === 'snapshot') {
    return OK;    // TODO
  } else if (body.log_type === 'result') {
    data = parseResult(body.data);
  } else {
    return ERROR;
  }

  await Promise.all([processRules(data), uploadToS3(data)]);
  return OK;
}

function logStatus(data) {
  for (const row of data) {
    const msg = `${row.calendarTime} ${row.filename}:${row.line} ${row.message}`;
    if (row.severity === '0') {
      console.info(msg);
    } else if (row.severity === '1') {
      console.warning(msg);
    } else {
      console.error(msg);
    }
  }
}

function parseResult(data) {
  // {
  //   "node_key": "...",
  //   "log_type": "result",
  //   "data": [
  //       {
  //           "name": "kubernetes_events",
  //           "calendarTime": "Sat May  8 00:44:15 2021 UTC",
  //           "unixTime": 1620434655,
  //           "action": "added",
  //           ...
  //           "columns": {"abc": "def", "xyz": "123", ...}
  //       },
  //       ...
  //   ]
  // }

  // Create: tableName -> partition -> rows
  // {
  //   "kubernetes_events": {
  //     "20210505": [{"abc": "def", "xyz": "123"}, ...]
  //   }
  // }
  const tables = {};
  for (const record of data) {
    const day = getDay(record.unixTime);
    const partitions = tables[record.name] || {};
    tables[record.name] = partitions;
    if (!partitions[day]) {
      partitions[day] = [];
    }

    const row = record.columns;
    row.calendarTime = record.calendarTime;
    row.unixTime = record.unixTime;
    row.added = record.action === 'added';
    partitions[day].push(row);
  }

  return tables;
}

function getDay(unixTime) {
  const date = new Date(unixTime * 1000);
  const month = date.getUTCMonth() + 1;
  let day = '' + date.getUTCFullYear();
  day += month < 10 ? ('0' + month) : month;
  day += date.getUTCDate() < 10 ? ('0' + date.getUTCDate()) : date.getUTCDate();

  return day;
}

async function uploadToS3(data) {
  // Format: tableName -> partition -> rows
  Object.keys(data).forEach(tableName => {
    const partitions = data[tableName];
    Object.keys(partitions).forEach(async day => {
      const rows = partitions[day];

      // Each JSON row should be on separate row
      let Body = '';
      rows.forEach(row => Body += JSON.stringify(row) + '\n');

      const id = crypto.randomBytes(20).toString('hex');
      const Key = `${tableName}/day=${day}/${id}.json`;

      for (let i = 0; i < 3; i++) {
        try {
          await s3.putObject({ Bucket, Key, ContentType, Body }).promise();
          break;
        } catch (err) {
          console.error('Error uploading to S3:', tableName, 'Retrying:', err);
        }
      }
    });
  });
}

async function processRules(data) {
  Object.keys(data).forEach(tableName => {
    const tableRules = RULES[tableName];
    if (!tableRules) {
      return;
    }

    const partitions = data[tableName];
    Object.keys(partitions).forEach(day => {
      partitions[day].forEach(row => {
        Object.keys(tableRules).forEach(async ruleName => {
          if (row.added && re.apply(tableRules[ruleName], row)) {
            const msg = JSON.stringify(row, 0, 2);
            console.info('Rule match:', ruleName, '. Data:', msg);
            try {
              await sns.publish({
                TopicArn,
                MessageStructure: 'json',
                Subject: 'Rule failed: ' + ruleName,
                Message: JSON.stringify({default: msg})
              }).promise();
            } catch (err) {
              console.error('Error publishing to SNS:', tableName, 'Rule:', ruleName, err);
            }
          }
        });
      });
    });
  });
}

module.exports = {
  handler,
  getRules,
  parseResult,
};