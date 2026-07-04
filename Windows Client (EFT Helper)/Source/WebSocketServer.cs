// EFTHelper, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null
// EFTHelper.WebSocketServer
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.WebSockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

public class WebSocketServer
{
	private HttpListener _listener;

	private List<WebSocket> _clients = new List<WebSocket>();

	private JavaScriptSerializer _json = new JavaScriptSerializer();

	private CancellationTokenSource _cancellationTokenSource;

	private bool _isRunning;

	public event Action<string, string> OnCommand;

	public WebSocketServer(string uriPrefix)
	{
		_listener = new HttpListener();
		_listener.Prefixes.Add(uriPrefix);
	}

	public async void Start()
	{
		if (_isRunning)
		{
			return;
		}
		_cancellationTokenSource = new CancellationTokenSource();
		_isRunning = true;
		_listener.Start();
		Console.WriteLine("Listening...");
		while (_isRunning)
		{
			try
			{
				HttpListenerContext context = await _listener.GetContextAsync();
				if (context.Request.IsWebSocketRequest)
				{
					ProcessRequest(context);
					continue;
				}
				context.Response.StatusCode = 400;
				context.Response.Close();
			}
			catch (HttpListenerException)
			{
				break;
			}
			catch (Exception ex2)
			{
				if (_isRunning)
				{
					Console.WriteLine("Listener Error: " + ex2.Message);
				}
			}
		}
	}

	private async void ProcessRequest(HttpListenerContext context)
	{
		WebSocketContext wsContext = null;
		try
		{
			wsContext = await context.AcceptWebSocketAsync(null);
			lock (_clients)
			{
				_clients.Add(wsContext.WebSocket);
			}
			Console.WriteLine("Client Connected");
			Broadcast(new
			{
				type = "log",
				message = "Client Connected to Helper"
			});
			await ReceiveLoop(wsContext.WebSocket);
		}
		catch (Exception ex)
		{
			Console.WriteLine("WebSocket Accept Error: " + ex.Message);
		}
		finally
		{
			if (wsContext != null)
			{
				lock (_clients)
				{
					_clients.Remove(wsContext.WebSocket);
				}
				wsContext.WebSocket.Dispose();
				Console.WriteLine("Client Disconnected");
			}
		}
	}

	private async Task ReceiveLoop(WebSocket ws)
	{
		byte[] buffer = new byte[4096];
		while (ws.State == WebSocketState.Open)
		{
			try
			{
				WebSocketReceiveResult result = await ws.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);
				if (result.MessageType == WebSocketMessageType.Close)
				{
					await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closing", CancellationToken.None);
					continue;
				}
				string msg = Encoding.UTF8.GetString(buffer, 0, result.Count);
				Console.WriteLine("[WS RECV] " + msg);
				HandleMessage(msg);
			}
			catch (Exception ex)
			{
				Console.WriteLine("Receive Error: " + ex.Message);
				break;
			}
		}
	}

	private void HandleMessage(string jsonMsg)
	{
		try
		{
			Dictionary<string, object> data = _json.Deserialize<Dictionary<string, object>>(jsonMsg);
			string action = (data.ContainsKey("action") ? (data["action"] as string) : null);
			string param = (data.ContainsKey("param") ? (data["param"] as string) : null);
			if (action != null)
			{
				this.OnCommand?.Invoke(action, param);
			}
		}
		catch (Exception ex)
		{
			Console.WriteLine("JSON Parse Error: " + ex.Message);
		}
	}

	public async void Broadcast(object data)
	{
		try
		{
			string json = _json.Serialize(data);
			if (!json.Contains("image"))
			{
				Console.WriteLine("[WS SEND] " + json);
			}
			byte[] buffer = Encoding.UTF8.GetBytes(json);
			List<WebSocket> toRemove = new List<WebSocket>();
			WebSocket[] clientArr;
			lock (_clients)
			{
				clientArr = _clients.ToArray();
			}
			WebSocket[] array = clientArr;
			foreach (WebSocket ws in array)
			{
				if (ws.State == WebSocketState.Open)
				{
					try
					{
						await ws.SendAsync(new ArraySegment<byte>(buffer), WebSocketMessageType.Text, endOfMessage: true, CancellationToken.None);
					}
					catch
					{
						toRemove.Add(ws);
					}
				}
				else
				{
					toRemove.Add(ws);
				}
			}
			if (toRemove.Count <= 0)
			{
				return;
			}
			lock (_clients)
			{
				toRemove.ForEach(delegate(WebSocket c)
				{
					_clients.Remove(c);
				});
			}
		}
		catch (Exception ex)
		{
			Console.WriteLine("Broadcast Error: " + ex.Message);
		}
	}

	public void Stop()
	{
		_isRunning = false;
		_cancellationTokenSource?.Cancel();
		lock (_clients)
		{
			foreach (WebSocket client in _clients)
			{
				try
				{
					if (client.State == WebSocketState.Open)
					{
						client.CloseAsync(WebSocketCloseStatus.NormalClosure, "Server stopping", CancellationToken.None).Wait(1000);
					}
					client.Dispose();
				}
				catch
				{
				}
			}
			_clients.Clear();
		}
		try
		{
			_listener.Stop();
			_listener.Close();
		}
		catch
		{
		}
	}
}
