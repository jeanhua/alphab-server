using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Collections.Concurrent;
using Fleck;

namespace Program
{
    class App
    {
        static void Main(String[] args)
        {
            int port = 0;
            while (true)
            {
                Console.WriteLine("请输入开放端口（1~65535）：");
                bool isInt = int.TryParse(Console.ReadLine(), out port);
                if (isInt && port >= 1 && port <= 65535)
                {
                    break;
                }
            }
            Console.OutputEncoding = Encoding.UTF8;
            var server = new WebSocket(port);
            server.Start();
        }
    }

    class MessageQueue
    {
        public IWebSocketConnection client;
        public string message;
        public MessageQueue(IWebSocketConnection client, string message)
        {
            this.client = client;
            this.message = message;
        }
    }
    public class WebSocket
    {
        private WebSocketServer listener;
        private Dictionary<IWebSocketConnection, String> listeners_key = new Dictionary<IWebSocketConnection, string>();
        private BlockingCollection<MessageQueue> message_queue = new BlockingCollection<MessageQueue>();
        private List<Thread> spreadThread = new List<Thread>();
        private int spreadThreadNum = 10; //传播线程数
        public WebSocket(int port)
        {
            IPAddress ipAddress = IPAddress.Any;
            listener = new WebSocketServer(string.Format("ws://0.0.0.0:{0}",port));
            listener.RestartAfterListenError = true;
        }
        public void Start()
        {
            // 绑定事件
            listener.Start(socket => {
                socket.OnOpen = () => onOpen(socket);
                socket.OnClose = () => onClose(socket);
                socket.OnMessage = message => onMessage(socket,message);
            });
            for (int i = 0; i < spreadThreadNum; i++)
            {
                spreadThread.Add(new Thread(SpreadMessage));
            }
            foreach(Thread thread in spreadThread)
            {
                thread.Start();
            }
        }

        private void onOpen(IWebSocketConnection socket)
        {
            Console.WriteLine("用户进入:{0}",socket.ConnectionInfo.ClientIpAddress);
        }

        private void onClose(IWebSocketConnection socket)
        {
            if(listeners_key.ContainsKey(socket))
            {
                listeners_key.Remove(socket);
            }
            Console.WriteLine("用户离开:{0}", socket.ConnectionInfo.ClientIpAddress);
        }

        private void onMessage(IWebSocketConnection socket,string message)
        {
            if (!listeners_key.ContainsKey(socket))
            {
                try
                {
                    var jsonMessage = JsonSerializer.Deserialize<Dictionary<string, string>>(message);
                    string type = jsonMessage["type"];
                    // 密钥交换
                    if (type == "connect")
                    {
                        string id = jsonMessage["id"];
                        string rsaKey = jsonMessage["public key"];
                        string aeskey = AESEncrypt.GenerateKey();
                        string aesKey_encrypt_base64 = RSAEncrypt.EncryptWithPublicKey(rsaKey, aeskey);
                        var messageReply = new Dictionary<string, string>();
                        messageReply.Add("type", "connect");
                        messageReply.Add("id", id);
                        messageReply.Add("AES key", aesKey_encrypt_base64);
                        socket.Send(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(messageReply)));
                        listeners_key[socket] = aeskey;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.ToString());
                }
            }
            //消息处理
            else
            {
                try
                {
                    string decrypt_message = AESEncrypt.DecryptBytes(System.Convert.FromBase64String(message), listeners_key[socket]);
                    var callback = new Dictionary<string, string>();
                    callback["type"] = "callback";
                    callback["id"] = JsonDocument.Parse(decrypt_message).RootElement.GetProperty("id").GetString();
                    callback["status"] = "success";
                    byte[] bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(callback));
                    socket.Send(Encoding.UTF8.GetBytes(AESEncrypt.EncryptBytes(bytes, listeners_key[socket])));
                    message_queue.Add(new MessageQueue(socket, decrypt_message));
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.ToString());
                }
            }
        }

        private void SpreadMessage()
        {
            while (true)
            {
                try
                {
                    var messagequeue = message_queue.Take();
                    var sourceClient = messagequeue.client;
                    var message = messagequeue.message;
                    foreach (var i in listeners_key)
                    {
                        if (i.Key == sourceClient)
                        {
                            continue;
                        }
                        i.Key.Send(Encoding.UTF8.GetBytes(AESEncrypt.EncryptBytes(Encoding.UTF8.GetBytes(message), listeners_key[i.Key])));
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("SpreadMessage:{0}", ex.Message);
                }
            }
        }
    }
}