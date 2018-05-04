# doorLock

The main handler must be configured before use:
1. MQTT must be set up on your device to publish RFID tag to trigger and be read by the lambda handler.
2. Appropriate S3 bucket must be created.
3. Appropriate DynamoDB table must be created.
