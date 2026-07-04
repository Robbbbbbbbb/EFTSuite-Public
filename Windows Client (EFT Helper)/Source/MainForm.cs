// EFTHelper, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null
// EFTHelper.MainForm
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Net;
using System.Windows.Forms;

public class MainForm : Form
{
	private KojakScanner _scanner;

	private WebSocketServer _server;

	private bool _listenerStarted;

	private bool _saveNextCapture;

	private int _port = 8888;

	private bool _isClosingToTray = true;

	private IContainer components;

	private Panel headerPanel;

	private Label titleLabel;

	private Label subtitleLabel;

	private GroupBox scannerGroupBox;

	private Panel scannerStatusPanel;

	private Panel scannerStatusIndicator;

	private Label scannerStatusLabel;

	private Button btnCheckScanner;

	private Button btnInitScanner;

	private Button btnTestCapture;

	private Button btnCancelCapture;

	private Button btnLedTest;
	private CheckBox chkBeeper;

	private PictureBox pbPreview;

	private Label lblCaptureInstruction;

	private GroupBox serverGroupBox;

	private Panel serverStatusPanel;

	private Panel serverStatusIndicator;

	private Label serverStatusLabel;

	private Label lblPort;

	private NumericUpDown numPort;

	private Button btnStartServer;

	private GroupBox logGroupBox;

	private TextBox txtLog;

	private Button btnClearLog;

	private NotifyIcon notifyIcon;

	private ContextMenuStrip trayContextMenu;

	private ToolStripMenuItem showMenuItem;

	private ToolStripMenuItem restartMenuItem;

	private ToolStripMenuItem reinitScannerMenuItem;

	private ToolStripSeparator separatorMenuItem;

	private ToolStripMenuItem quitMenuItem;

	public MainForm()
	{
		InitializeComponent();
		InitializeApplication();
	}

	private void InitializeApplication()
	{
		_scanner = new KojakScanner();
		_scanner.OnPreviewImage += delegate(string base64)
		{
			UpdatePreviewImage(base64);
			if (_listenerStarted)
			{
				_server?.Broadcast(new
				{
					type = "preview",
					image = base64
				});
			}
		};
		_scanner.OnResultImage += delegate(string base64, string fingerName, int quality)
		{
			UpdatePreviewImage(base64);
			if (_saveNextCapture)
			{
				try
				{
					string text = $"test_capture_{DateTime.Now:yyyyMMdd_HHmmss}.png";
					string text2 = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, text);
					File.WriteAllBytes(text2, Convert.FromBase64String(base64));
					AddLogMessage("[Test] Image saved to " + text);
					_saveNextCapture = false;
					UpdateTestCaptureUI(isCapturing: false);
					Process.Start("explorer.exe", $"/select,\"{text2}\"");
				}
				catch (Exception ex)
				{
					AddLogMessage("[Test] Failed to save image: " + ex.Message);
				}
			}
			if (_listenerStarted)
			{
				_server?.Broadcast(new
				{
					type = "result",
					image = base64,
					finger = fingerName,
					quality = quality
				});
			}
		};
		_scanner.OnFingerResult += delegate(KojakScanner.FingerResult r)
		{
			UpdatePreviewImage(r.Base64);
			if (_listenerStarted)
			{
				_server?.Broadcast(new
				{
					type       = "capture_result",
					finger     = r.FingerPosition,
					impression = r.Impression,
					rolled     = r.Rolled,
					quality    = r.Quality,
					image      = r.Base64
				});
			}
		};
		_scanner.OnStatusMessage += delegate(string msg)
		{
			AddLogMessage("[Scanner] " + msg);
			if (_listenerStarted)
			{
				_server?.Broadcast(new
				{
					type = "status",
					message = msg
				});
			}
			UpdateScannerStatus();
		};
		_scanner.Initialize();
		UpdateScannerStatus();
		UpdatePortDisplay();
	}

	private void InitializeServer()
	{
		_server = new WebSocketServer($"http://*:{_port}/");
		_server.OnCommand += delegate(string cmd, string param)
		{
			switch (cmd)
			{
			case "START_CAPTURE":
				_scanner.StartCapture(param);
				break;
			case "ROLLED":
				_scanner.StartRolledSequence();
				break;
			case "CANCEL":
				_scanner.CancelCapture();
				break;
			case "INIT":
				_scanner.Initialize();
				break;
			}
		};
	}

	private void UpdateScannerStatus()
	{
		if (base.InvokeRequired)
		{
			Invoke(new Action(UpdateScannerStatus));
			return;
		}
		bool initialized = _scanner?.IsInitialized ?? false;
		scannerStatusIndicator.BackColor = (initialized ? Color.FromArgb(46, 204, 113) : Color.FromArgb(231, 76, 60));
		scannerStatusLabel.Text = (initialized ? "Scanner Connected" : "Scanner Not Found");
		btnInitScanner.Enabled = true;
		btnTestCapture.Enabled = initialized && !_saveNextCapture;
	}

	private void UpdateServerStatus()
	{
		if (base.InvokeRequired)
		{
			Invoke(new Action(UpdateServerStatus));
			return;
		}
		Color colorBrand = ColorTranslator.FromHtml("#bada55");
		Color colorStop = Color.FromArgb(192, 57, 43);
		serverStatusIndicator.BackColor = (_listenerStarted ? Color.FromArgb(46, 204, 113) : colorStop);
		serverStatusLabel.Text = (_listenerStarted ? ("Listening on port " + _port) : "Web Helper Stopped");
		btnStartServer.Text = (_listenerStarted ? "Stop Web Helper" : "Start Web Helper");
		btnStartServer.BackColor = (_listenerStarted ? colorStop : colorBrand);
		btnStartServer.ForeColor = (_listenerStarted ? Color.White : Color.Black);
		numPort.Enabled = !_listenerStarted;
	}

	private void UpdatePortDisplay()
	{
		if (base.InvokeRequired)
		{
			Invoke(new Action(UpdatePortDisplay));
		}
		else
		{
			numPort.Value = _port;
		}
	}

	private void UpdateTestCaptureUI(bool isCapturing)
	{
		if (base.InvokeRequired)
		{
			Invoke(new Action<bool>(UpdateTestCaptureUI), isCapturing);
			return;
		}
		bool initialized = _scanner?.IsInitialized ?? false;
		btnTestCapture.Enabled = !isCapturing && initialized;
		btnCancelCapture.Visible = isCapturing;
		lblCaptureInstruction.Visible = isCapturing;
		if (isCapturing)
		{
			lblCaptureInstruction.Text = "PLACE LEFT HAND SLAP\nON SCANNER";
			pbPreview.Image = null;
		}
		else
		{
			lblCaptureInstruction.Text = "Capture Complete.";
		}
	}

	private void UpdatePreviewImage(string base64)
	{
		if (base.InvokeRequired)
		{
			Invoke(new Action<string>(UpdatePreviewImage), base64);
			return;
		}
		try
		{
			using MemoryStream ms = new MemoryStream(Convert.FromBase64String(base64));
			Image img = Image.FromStream(ms);
			if (pbPreview.Image != null)
			{
				pbPreview.Image.Dispose();
			}
			pbPreview.Image = img;
		}
		catch
		{
		}
	}

	public void AddLogMessage(string message)
	{
		if (base.InvokeRequired)
		{
			Invoke(new Action<string>(AddLogMessage), message);
		}
		else
		{
			string timestamp = DateTime.Now.ToString("HH:mm:ss");
			txtLog.AppendText($"[{timestamp}] {message}{Environment.NewLine}");
			txtLog.ScrollToCaret();
		}
	}

	private void btnCheckScanner_Click(object sender, EventArgs e)
	{
		KojakScanner scanner = _scanner;
		if (scanner != null && scanner.IsInitialized)
		{
			AddLogMessage("Scanner is already initialized and ready.");
			UpdateScannerStatus();
			return;
		}
		int count = _scanner.GetDeviceCount();
		if (count > 0)
		{
			AddLogMessage($"Found {count} scanner(s) connected but not initialized.");
			if (MessageBox.Show($"Found {count} scanner(s) connected.\n\nWould you like to initialize the device now?", "Scanner Detected", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
			{
				btnInitScanner_Click(null, null);
			}
		}
		else
		{
			AddLogMessage("No scanners detected via USB.");
			MessageBox.Show("No scanners were detected. Please ensure your device is plugged in.", "Not Found", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
		}
		UpdateScannerStatus();
	}

	private void btnInitScanner_Click(object sender, EventArgs e)
	{
		AddLogMessage("Reinitializing scanner...");
		_scanner?.Dispose();
		_scanner?.Initialize();
		UpdateScannerStatus();
	}

	private void btnTestCapture_Click(object sender, EventArgs e)
	{
		KojakScanner scanner = _scanner;
		if (scanner == null || !scanner.IsInitialized)
		{
			AddLogMessage("Device not initialized. Try reinitializing first.");
			return;
		}
		AddLogMessage("Starting Test Capture (L_SLAP)...");
		_saveNextCapture = true;
		UpdateTestCaptureUI(isCapturing: true);
		if (!_scanner.StartCapture("L_SLAP"))
		{
			_saveNextCapture = false;
			UpdateTestCaptureUI(isCapturing: false);
			AddLogMessage("Failed to start capture.");
		}
	}

	private void btnCancelCapture_Click(object sender, EventArgs e)
	{
		_scanner?.CancelCapture();
		_saveNextCapture = false;
		UpdateTestCaptureUI(isCapturing: false);
		AddLogMessage("Capture cancelled by user.");
	}

	private void btnStartServer_Click(object sender, EventArgs e)
	{
		if (!_listenerStarted)
		{
			try
			{
				_port = (int)numPort.Value;
				InitializeServer();
				_server.Start();
				_listenerStarted = true;
				AddLogMessage("Web Helper Started on port " + _port);
				UpdateServerStatus();
				return;
			}
			catch (Exception ex)
			{
				string msg = ex.Message;
				if (ex is HttpListenerException && (ex as HttpListenerException).ErrorCode == 5)
				{
					msg = "Access Denied. Please run EFT Helper as Administrator to listen on all interfaces.";
				}
				else if (ex is HttpListenerException && (ex as HttpListenerException).ErrorCode == 50)
				{
					msg = "The request is not supported. Try a different port or check if another service is using this one.";
				}
				AddLogMessage("Error: " + msg);
				MessageBox.Show(msg, "Server Error", MessageBoxButtons.OK, MessageBoxIcon.Hand);
				return;
			}
		}
		try
		{
			_server?.Stop();
			_listenerStarted = false;
			AddLogMessage("Web Helper Stopped");
			UpdateServerStatus();
		}
		catch (Exception ex2)
		{
			AddLogMessage("Error stopping server: " + ex2.Message);
		}
	}

	private void numPort_ValueChanged(object sender, EventArgs e)
	{
		_port = (int)numPort.Value;
	}

	private void MainForm_FormClosing(object sender, FormClosingEventArgs e)
	{
		if (_isClosingToTray && e.CloseReason == CloseReason.UserClosing)
		{
			e.Cancel = true;
			Hide();
			notifyIcon.Visible = true;
		}
	}

	private void notifyIcon_DoubleClick(object sender, EventArgs e)
	{
		ShowMainWindow();
	}

	private void showMenuItem_Click(object sender, EventArgs e)
	{
		ShowMainWindow();
	}

	private void restartMenuItem_Click(object sender, EventArgs e)
	{
		AddLogMessage("Restarting EFT Helper service...");
		if (_listenerStarted)
		{
			_server?.Stop();
			_listenerStarted = false;
		}
		_scanner?.Dispose();
		_scanner?.Initialize();
		InitializeServer();
		_server.Start();
		_listenerStarted = true;
		AddLogMessage("EFT Helper service restarted.");
		UpdateScannerStatus();
		UpdateServerStatus();
	}

	private void reinitScannerMenuItem_Click(object sender, EventArgs e)
	{
		AddLogMessage("Reinitializing scanner from tray...");
		_scanner?.Dispose();
		_scanner?.Initialize();
		UpdateScannerStatus();
	}

	private void quitMenuItem_Click(object sender, EventArgs e)
	{
		_isClosingToTray = false;
		_scanner?.Dispose();
		_server?.Stop();
		if (pbPreview.Image != null)
		{
			pbPreview.Image.Dispose();
		}
		notifyIcon.Visible = false;
		Application.Exit();
	}

	private void ShowMainWindow()
	{
		Show();
		base.WindowState = FormWindowState.Normal;
		BringToFront();
		Activate();
	}

	protected override void OnLoad(EventArgs e)
	{
		base.OnLoad(e);
		UpdateServerStatus();
	}

	protected override void Dispose(bool disposing)
	{
		if (disposing && components != null)
		{
			components.Dispose();
		}
		base.Dispose(disposing);
	}

	private void InitializeComponent()
	{
		this.components = new System.ComponentModel.Container();
		System.Drawing.Color colorBrand = System.Drawing.ColorTranslator.FromHtml("#bada55");
		System.Drawing.Color colorBg = System.Drawing.ColorTranslator.FromHtml("#121212");
		System.Drawing.Color colorPanel = System.Drawing.ColorTranslator.FromHtml("#1e1e1e");
		System.Drawing.Color colorButtonDark = System.Drawing.ColorTranslator.FromHtml("#333333");
		System.Drawing.Color colorTextSecondary = System.Drawing.ColorTranslator.FromHtml("#aaaaaa");
		this.Text = "EFT Helper";
		base.Size = new System.Drawing.Size(600, 850);
		this.MinimumSize = new System.Drawing.Size(550, 750);
		base.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
		this.BackColor = colorBg;
		this.ForeColor = System.Drawing.Color.White;
		this.Font = new System.Drawing.Font("Segoe UI", 10f, System.Drawing.FontStyle.Regular);
		base.FormClosing += new System.Windows.Forms.FormClosingEventHandler(MainForm_FormClosing);
		this.headerPanel = new System.Windows.Forms.Panel
		{
			Dock = System.Windows.Forms.DockStyle.Top,
			Height = 100,
			BackColor = colorPanel,
			Padding = new System.Windows.Forms.Padding(20)
		};
		this.titleLabel = new System.Windows.Forms.Label
		{
			Text = "EFT Helper",
			Font = new System.Drawing.Font("Segoe UI", 24f, System.Drawing.FontStyle.Bold),
			ForeColor = colorBrand,
			AutoSize = true,
			Location = new System.Drawing.Point(20, 15)
		};
		this.subtitleLabel = new System.Windows.Forms.Label
		{
			Text = "Fingerprint Scanner Bridge for EFT Suite",
			Font = new System.Drawing.Font("Segoe UI", 10f, System.Drawing.FontStyle.Regular),
			ForeColor = colorTextSecondary,
			AutoSize = true,
			Location = new System.Drawing.Point(24, 62)
		};
		this.headerPanel.Controls.Add(this.titleLabel);
		this.headerPanel.Controls.Add(this.subtitleLabel);
		this.scannerGroupBox = new System.Windows.Forms.GroupBox
		{
			Text = "  Scanner Status  ",
			ForeColor = colorTextSecondary,
			Font = new System.Drawing.Font("Segoe UI", 11f, System.Drawing.FontStyle.Bold),
			Location = new System.Drawing.Point(20, 115),
			Size = new System.Drawing.Size(540, 365),
			Anchor = (System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right),
			FlatStyle = System.Windows.Forms.FlatStyle.Flat
		};
		this.scannerStatusPanel = new System.Windows.Forms.Panel
		{
			Location = new System.Drawing.Point(20, 30),
			Size = new System.Drawing.Size(500, 35),
			Anchor = (System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right)
		};
		this.scannerStatusIndicator = new System.Windows.Forms.Panel
		{
			Size = new System.Drawing.Size(16, 16),
			Location = new System.Drawing.Point(0, 8),
			BackColor = System.Drawing.Color.FromArgb(231, 76, 60)
		};
		this.MakeCircular(this.scannerStatusIndicator);
		this.scannerStatusLabel = new System.Windows.Forms.Label
		{
			Text = "Scanner Not Found",
			Font = new System.Drawing.Font("Segoe UI", 11f, System.Drawing.FontStyle.Bold),
			ForeColor = System.Drawing.Color.White,
			AutoSize = true,
			Location = new System.Drawing.Point(25, 5)
		};
		this.scannerStatusPanel.Controls.Add(this.scannerStatusIndicator);
		this.scannerStatusPanel.Controls.Add(this.scannerStatusLabel);
		this.pbPreview = new System.Windows.Forms.PictureBox
		{
			Location = new System.Drawing.Point(20, 70),
			Size = new System.Drawing.Size(200, 230),
			BackColor = System.Drawing.Color.Black,
			SizeMode = System.Windows.Forms.PictureBoxSizeMode.Zoom,
			BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle
		};
		this.lblCaptureInstruction = new System.Windows.Forms.Label
		{
			Text = "Ready for capture.",
			Font = new System.Drawing.Font("Segoe UI", 12f, System.Drawing.FontStyle.Bold),
			ForeColor = colorBrand,
			Location = new System.Drawing.Point(240, 80),
			Size = new System.Drawing.Size(280, 60),
			TextAlign = System.Drawing.ContentAlignment.TopLeft,
			Visible = false
		};
		this.btnCheckScanner = this.CreateStyledButton("Check Status", new System.Drawing.Point(240, 150), new System.Drawing.Size(130, 35), colorButtonDark, System.Drawing.Color.White);
		this.btnCheckScanner.Click += new System.EventHandler(btnCheckScanner_Click);
		this.btnInitScanner = this.CreateStyledButton("Initialize", new System.Drawing.Point(380, 150), new System.Drawing.Size(130, 35), colorButtonDark, System.Drawing.Color.White);
		this.btnInitScanner.Click += new System.EventHandler(btnInitScanner_Click);
		this.btnTestCapture = this.CreateStyledButton("Test Capture", new System.Drawing.Point(240, 200), new System.Drawing.Size(270, 45), colorBrand, System.Drawing.Color.Black);
		this.btnTestCapture.Click += new System.EventHandler(btnTestCapture_Click);
		this.btnCancelCapture = this.CreateStyledButton("Cancel Capture", new System.Drawing.Point(240, 200), new System.Drawing.Size(270, 45), System.Drawing.Color.FromArgb(192, 57, 43), System.Drawing.Color.White);
		this.btnCancelCapture.Click += new System.EventHandler(btnCancelCapture_Click);
		this.btnCancelCapture.Visible = false;
		this.btnLedTest = this.CreateStyledButton("LED Test", new System.Drawing.Point(240, 258), new System.Drawing.Size(130, 32), System.Drawing.Color.FromArgb(44, 62, 80), System.Drawing.Color.FromArgb(78, 205, 196));
		this.btnLedTest.Click += new System.EventHandler(btnLedTest_Click);
		this.chkBeeper = new System.Windows.Forms.CheckBox
		{
			Text      = "Beep on capture",
			Checked   = true,
			ForeColor = System.Drawing.Color.White,
			BackColor = System.Drawing.Color.Transparent,
			Location  = new System.Drawing.Point(380, 265),
			Size      = new System.Drawing.Size(150, 22),
			Font      = new System.Drawing.Font("Segoe UI", 8.5f)
		};
		this.chkBeeper.CheckedChanged += (s, e) => { if (_scanner != null) _scanner.BeeperEnabled = this.chkBeeper.Checked; };
		this.scannerGroupBox.Controls.Add(this.scannerStatusPanel);
		this.scannerGroupBox.Controls.Add(this.pbPreview);
		this.scannerGroupBox.Controls.Add(this.lblCaptureInstruction);
		this.scannerGroupBox.Controls.Add(this.btnCheckScanner);
		this.scannerGroupBox.Controls.Add(this.btnInitScanner);
		this.scannerGroupBox.Controls.Add(this.btnTestCapture);
		this.scannerGroupBox.Controls.Add(this.btnCancelCapture);
		this.scannerGroupBox.Controls.Add(this.btnLedTest);
		this.scannerGroupBox.Controls.Add(this.chkBeeper);
		this.serverGroupBox = new System.Windows.Forms.GroupBox
		{
			Text = "  Web Helper Service  ",
			ForeColor = colorTextSecondary,
			Font = new System.Drawing.Font("Segoe UI", 11f, System.Drawing.FontStyle.Bold),
			Location = new System.Drawing.Point(20, 450),
			Size = new System.Drawing.Size(540, 130),
			Anchor = (System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right),
			FlatStyle = System.Windows.Forms.FlatStyle.Flat
		};
		this.serverStatusPanel = new System.Windows.Forms.Panel
		{
			Location = new System.Drawing.Point(20, 35),
			Size = new System.Drawing.Size(500, 40),
			Anchor = (System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right)
		};
		this.serverStatusIndicator = new System.Windows.Forms.Panel
		{
			Size = new System.Drawing.Size(16, 16),
			Location = new System.Drawing.Point(0, 10),
			BackColor = System.Drawing.Color.FromArgb(231, 76, 60)
		};
		this.MakeCircular(this.serverStatusIndicator);
		this.serverStatusLabel = new System.Windows.Forms.Label
		{
			Text = "Web Helper Stopped",
			Font = new System.Drawing.Font("Segoe UI", 11f, System.Drawing.FontStyle.Bold),
			ForeColor = System.Drawing.Color.White,
			AutoSize = true,
			Location = new System.Drawing.Point(25, 7)
		};
		this.serverStatusPanel.Controls.Add(this.serverStatusIndicator);
		this.serverStatusPanel.Controls.Add(this.serverStatusLabel);
		this.lblPort = new System.Windows.Forms.Label
		{
			Text = "Port:",
			Font = new System.Drawing.Font("Segoe UI", 10f, System.Drawing.FontStyle.Regular),
			ForeColor = System.Drawing.Color.White,
			AutoSize = true,
			Location = new System.Drawing.Point(20, 88)
		};
		this.numPort = new System.Windows.Forms.NumericUpDown
		{
			Minimum = 1024m,
			Maximum = 65535m,
			Value = 8888m,
			Font = new System.Drawing.Font("Segoe UI", 10f, System.Drawing.FontStyle.Regular),
			Location = new System.Drawing.Point(65, 85),
			Size = new System.Drawing.Size(80, 25),
			BackColor = colorPanel,
			ForeColor = System.Drawing.Color.White,
			BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle
		};
		this.numPort.ValueChanged += new System.EventHandler(numPort_ValueChanged);
		this.btnStartServer = this.CreateStyledButton("Start Web Helper", new System.Drawing.Point(160, 80), new System.Drawing.Size(180, 35), colorBrand, System.Drawing.Color.Black);
		this.btnStartServer.Click += new System.EventHandler(btnStartServer_Click);
		this.serverGroupBox.Controls.Add(this.serverStatusPanel);
		this.serverGroupBox.Controls.Add(this.lblPort);
		this.serverGroupBox.Controls.Add(this.numPort);
		this.serverGroupBox.Controls.Add(this.btnStartServer);
		this.logGroupBox = new System.Windows.Forms.GroupBox
		{
			Text = "  Activity Log  ",
			ForeColor = colorTextSecondary,
			Font = new System.Drawing.Font("Segoe UI", 11f, System.Drawing.FontStyle.Bold),
			Location = new System.Drawing.Point(20, 595),
			Size = new System.Drawing.Size(540, 180),
			Anchor = (System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right),
			FlatStyle = System.Windows.Forms.FlatStyle.Flat
		};
		this.txtLog = new System.Windows.Forms.TextBox
		{
			Multiline = true,
			ReadOnly = true,
			ScrollBars = System.Windows.Forms.ScrollBars.Vertical,
			Location = new System.Drawing.Point(20, 30),
			Size = new System.Drawing.Size(500, 110),
			Anchor = (System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right),
			BackColor = colorBg,
			ForeColor = colorTextSecondary,
			Font = new System.Drawing.Font("Consolas", 9f, System.Drawing.FontStyle.Regular),
			BorderStyle = System.Windows.Forms.BorderStyle.None
		};
		this.btnClearLog = this.CreateStyledButton("Clear", new System.Drawing.Point(440, 145), new System.Drawing.Size(80, 25), colorButtonDark, System.Drawing.Color.White);
		this.btnClearLog.Anchor = System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right;
		this.btnClearLog.Click += delegate
		{
			this.txtLog.Clear();
		};
		this.logGroupBox.Controls.Add(this.txtLog);
		this.logGroupBox.Controls.Add(this.btnClearLog);
		this.notifyIcon = new System.Windows.Forms.NotifyIcon(this.components)
		{
			Text = "EFT Helper",
			Visible = false
		};
		this.notifyIcon.DoubleClick += new System.EventHandler(notifyIcon_DoubleClick);
		using (System.Drawing.Bitmap bmp = new System.Drawing.Bitmap(32, 32))
		{
			using (System.Drawing.Graphics g = System.Drawing.Graphics.FromImage(bmp))
			{
				g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
				g.Clear(System.Drawing.Color.Transparent);
				using System.Drawing.Pen pen = new System.Drawing.Pen(colorBrand, 2f);
				g.DrawEllipse(pen, 4, 4, 24, 24);
				g.DrawEllipse(pen, 8, 8, 16, 16);
				g.DrawEllipse(pen, 12, 12, 8, 8);
			}
			this.notifyIcon.Icon = System.Drawing.Icon.FromHandle(bmp.GetHicon());
		}
		this.trayContextMenu = new System.Windows.Forms.ContextMenuStrip();
		this.trayContextMenu.BackColor = colorPanel;
		this.trayContextMenu.ForeColor = System.Drawing.Color.White;
		this.showMenuItem = new System.Windows.Forms.ToolStripMenuItem("Show EFT Helper");
		this.showMenuItem.Click += new System.EventHandler(showMenuItem_Click);
		this.restartMenuItem = new System.Windows.Forms.ToolStripMenuItem("Restart EFT Helper Service");
		this.restartMenuItem.Click += new System.EventHandler(restartMenuItem_Click);
		this.reinitScannerMenuItem = new System.Windows.Forms.ToolStripMenuItem("Reinitialize Scanner");
		this.reinitScannerMenuItem.Click += new System.EventHandler(reinitScannerMenuItem_Click);
		this.quitMenuItem = new System.Windows.Forms.ToolStripMenuItem("Quit EFT Helper");
		this.quitMenuItem.Click += new System.EventHandler(quitMenuItem_Click);
		this.trayContextMenu.Items.AddRange(new System.Windows.Forms.ToolStripItem[6]
		{
			this.showMenuItem,
			new System.Windows.Forms.ToolStripSeparator(),
			this.restartMenuItem,
			this.reinitScannerMenuItem,
			new System.Windows.Forms.ToolStripSeparator(),
			this.quitMenuItem
		});
		this.notifyIcon.ContextMenuStrip = this.trayContextMenu;
		base.Controls.Add(this.logGroupBox);
		base.Controls.Add(this.serverGroupBox);
		base.Controls.Add(this.scannerGroupBox);
		base.Controls.Add(this.headerPanel);
		using System.Drawing.Bitmap bmp2 = new System.Drawing.Bitmap(32, 32);
		using (System.Drawing.Graphics g2 = System.Drawing.Graphics.FromImage(bmp2))
		{
			g2.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
			g2.Clear(colorPanel);
			using System.Drawing.Pen pen2 = new System.Drawing.Pen(colorBrand, 2f);
			g2.DrawEllipse(pen2, 4, 4, 24, 24);
			g2.DrawEllipse(pen2, 8, 8, 16, 16);
			g2.DrawEllipse(pen2, 12, 12, 8, 8);
		}
		base.Icon = System.Drawing.Icon.FromHandle(bmp2.GetHicon());
	}

	private Button CreateStyledButton(string text, Point location, Size size, Color backColor, Color foreColor)
	{
		Button btn = new Button
		{
			Text = text,
			Location = location,
			Size = size,
			BackColor = backColor,
			ForeColor = foreColor,
			FlatStyle = FlatStyle.Flat,
			Font = new Font("Segoe UI", 10f, FontStyle.Bold),
			Cursor = Cursors.Hand
		};
		btn.FlatAppearance.BorderSize = 0;
		GraphicsPath path = new GraphicsPath();
		int radius = 8;
		path.AddArc(0, 0, radius, radius, 180f, 90f);
		path.AddArc(btn.Width - radius, 0, radius, radius, 270f, 90f);
		path.AddArc(btn.Width - radius, btn.Height - radius, radius, radius, 0f, 90f);
		path.AddArc(0, btn.Height - radius, radius, radius, 90f, 90f);
		path.CloseFigure();
		btn.Region = new Region(path);
		return btn;
	}

	private void MakeCircular(Panel panel)
	{
		GraphicsPath path = new GraphicsPath();
		path.AddEllipse(0, 0, panel.Width, panel.Height);
		panel.Region = new Region(path);
	}
	private void btnLedTest_Click(object sender, EventArgs e)
	{
		if (_scanner == null || !_scanner.IsInitialized)
		{
			AddLogMessage("Initialize scanner first before opening LED Test.");
			return;
		}
		var form = new LedTestForm(_scanner);
		form.Show(this);
	}

}
