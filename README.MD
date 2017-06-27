# AWS IoT service signature utility

## How to use
* Use with paho javascript library
* Fill in your own key/secret and endpoint

```
<html>
  <body>
        <script src="./aws-iot-sign.js"></script>
        <script src="./mqttws31.js"></script>
        <script type="text/javascript">
        var credentials = 
            {
                accessKeyId: '<your_key>', 
                secretAccessKey: '<your_secret>',
                get: (callback) =>  {
                  callback();
                }
            };

        var iotSignUtil = AWSIoTSign.getUtil('ap-northeast-1', '<your_endpoint>.iot.ap-northeast-1.amazonaws.com', credentials);

        iotSignUtil.getSignedUrl(15, (err, url) => {
            console.log('Connecting to', url);
            var client = new Paho.MQTT.Client(url, 'clientId');
            var connectOptions = {
                onSuccess: function(){
                    console.log('connected');
                    client.subscribe("iotbutton/001");
                },
                useSSL: true,
                timeout: 3,
                mqttVersion: 4,
                onFailure: function() {
                    console.log('failed');
                }
            };
            client.connect(connectOptions);

            client.onMessageArrived = onMessageArrived;
        });

        function onMessageArrived(message) {
          console.log("onMessageArrived:"+message.payloadString);
        }       
        </script> 
  </body>
</html>
```

## How to build
```
$ npm run build
```