// EFTHelper — LED Test Panel
// Lets you toggle every individual LED bit and see what it does on the scanner hardware.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using IBscanUltimate;

public class LedTestForm : Form
{
	private readonly KojakScanner _scanner;
	private uint _currentMask = 0;
	private bool _syncing = false;

	private Label lblMask;
	private readonly List<(CheckBox cb, uint bit)> _ledItems = new List<(CheckBox, uint)>();

	// ---- LED catalogue ----
	// Each entry: (display name, bit value, group name)
	private static readonly (string group, string name, uint bit)[] LedCatalogue =
	{
		// System LEDs
		("System", "INIT_BLUE  0x01",    0x00000001u),
		("System", "SCAN_GREEN 0x02",    0x00000002u),

		// Curve / Progress (overlapping constants — same hardware bit)
		("Curve / Progress", "0x10  CURVE_RED  / PROG_ROLL",    0x00000010u),
		("Curve / Progress", "0x20  CURVE_GRN  / PROG_LEFT",    0x00000020u),
		("Curve / Progress", "0x40  CURVE_BLU  / PROG_THUMB",   0x00000040u),
		("Curve / Progress", "0x80  PROG_RIGHT",                 0x00000080u),

		// Right hand — Green
		("Right Hand · Green", "R Thumb",  DLL.IBSU_LED_F_RIGHT_THUMB_GREEN),
		("Right Hand · Green", "R Index",  DLL.IBSU_LED_F_RIGHT_INDEX_GREEN),
		("Right Hand · Green", "R Middle", DLL.IBSU_LED_F_RIGHT_MIDDLE_GREEN),
		("Right Hand · Green", "R Ring",   DLL.IBSU_LED_F_RIGHT_RING_GREEN),
		("Right Hand · Green", "R Little", DLL.IBSU_LED_F_RIGHT_LITTLE_GREEN),

		// Right hand — Red
		("Right Hand · Red",   "R Thumb",  DLL.IBSU_LED_F_RIGHT_THUMB_RED),
		("Right Hand · Red",   "R Index",  DLL.IBSU_LED_F_RIGHT_INDEX_RED),
		("Right Hand · Red",   "R Middle", DLL.IBSU_LED_F_RIGHT_MIDDLE_RED),
		("Right Hand · Red",   "R Ring",   DLL.IBSU_LED_F_RIGHT_RING_RED),
		("Right Hand · Red",   "R Little", DLL.IBSU_LED_F_RIGHT_LITTLE_RED),

		// Left hand — Green
		("Left Hand · Green",  "L Thumb",  DLL.IBSU_LED_F_LEFT_THUMB_GREEN),
		("Left Hand · Green",  "L Index",  DLL.IBSU_LED_F_LEFT_INDEX_GREEN),
		("Left Hand · Green",  "L Middle", DLL.IBSU_LED_F_LEFT_MIDDLE_GREEN),
		("Left Hand · Green",  "L Ring",   DLL.IBSU_LED_F_LEFT_RING_GREEN),
		("Left Hand · Green",  "L Little", DLL.IBSU_LED_F_LEFT_LITTLE_GREEN),

		// Left hand — Red
		("Left Hand · Red",    "L Thumb",  DLL.IBSU_LED_F_LEFT_THUMB_RED),
		("Left Hand · Red",    "L Index",  DLL.IBSU_LED_F_LEFT_INDEX_RED),
		("Left Hand · Red",    "L Middle", DLL.IBSU_LED_F_LEFT_MIDDLE_RED),
		("Left Hand · Red",    "L Ring",   DLL.IBSU_LED_F_LEFT_RING_RED),
		("Left Hand · Red",    "L Little", DLL.IBSU_LED_F_LEFT_LITTLE_RED),

		// Blink modifiers
		("Blink Modifiers", "BLINK_GREEN 0x10000000", DLL.IBSU_LED_F_BLINK_GREEN),
		("Blink Modifiers", "BLINK_RED   0x20000000", DLL.IBSU_LED_F_BLINK_RED),
	};

	public LedTestForm(KojakScanner scanner)
	{
		_scanner = scanner;
		BuildUI();
	}

	// ---- UI construction ----

	private void BuildUI()
	{
		this.Text            = "LED Test Panel";
		this.Size            = new Size(960, 640);
		this.MinimumSize     = new Size(880, 580);
		this.BackColor       = Color.FromArgb(28, 28, 35);
		this.ForeColor       = Color.White;
		this.Font            = new Font("Segoe UI", 9f);
		this.StartPosition   = FormStartPosition.CenterScreen;
		this.FormBorderStyle = FormBorderStyle.Sizable;

		// Title
		var title = new Label
		{
			Text      = "LED Test Panel",
			ForeColor = Color.FromArgb(78, 205, 196),
			Font      = new Font("Segoe UI", 15f, FontStyle.Bold),
			AutoSize  = true,
			Location  = new Point(16, 12)
		};
		this.Controls.Add(title);

		// Mask display
		lblMask = new Label
		{
			Text      = "Mask: 0x00000000",
			ForeColor = Color.LightGreen,
			Font      = new Font("Consolas", 11f),
			AutoSize  = true,
			Location  = new Point(16, 48)
		};
		this.Controls.Add(lblMask);

		// Action buttons
		int bx = 400;
		var btnAllOff = MakeBtn("All OFF", new Point(bx, 40));
		btnAllOff.Click += (s, e) => { _currentMask = DLL.IBSU_LED_NONE; SyncAndApply(); };

		var btnAllOn = MakeBtn("All ON", new Point(bx + 110, 40));
		btnAllOn.BackColor = Color.FromArgb(50, 80, 50);
		btnAllOn.Click += (s, e) => { _currentMask = DLL.IBSU_LED_ALL; SyncAndApply(); };

		var btnClose = MakeBtn("Close", new Point(bx + 220, 40));
		btnClose.Click += (s, e) => this.Close();

		this.Controls.AddRange(new Control[] { btnAllOff, btnAllOn, btnClose });

		// Separator line
		var sep = new Panel { BackColor = Color.FromArgb(60, 60, 80), Location = new Point(0, 80), Size = new Size(960, 1) };
		this.Controls.Add(sep);

		// Build grouped checkboxes inside a scrollable panel
		var scroll = new Panel
		{
			Location   = new Point(0, 85),
			Size       = new Size(960, 520),
			AutoScroll = true,
			Anchor     = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right
		};
		this.Controls.Add(scroll);

		int y = 8;
		string lastGroup = null;

		// Columns: 5 checkboxes per row, each 175px wide
		int colW  = 175;
		int rowH  = 24;
		int col   = 0;
		int groupY = y;

		foreach (var (grp, name, bit) in LedCatalogue)
		{
			// Group header
			if (grp != lastGroup)
			{
				if (col > 0) { y += rowH; col = 0; }  // finish current row
				y += 4;
				var lbl = new Label
				{
					Text      = "▸ " + grp,
					ForeColor = Color.FromArgb(78, 205, 196),
					Font      = new Font("Segoe UI", 8.5f, FontStyle.Bold),
					AutoSize  = true,
					Location  = new Point(12, y)
				};
				scroll.Controls.Add(lbl);
				y    += 20;
				col   = 0;
				lastGroup = grp;
			}

			// Checkbox
			uint capturedBit = bit;
			var cb = new CheckBox
			{
				Text      = name,
				ForeColor = Color.White,
				BackColor = Color.Transparent,
				Location  = new Point(12 + col * colW, y),
				Size      = new Size(colW - 4, rowH),
				Checked   = false
			};
			cb.CheckedChanged += (s, e) =>
			{
				if (_syncing) return;
				if (cb.Checked) _currentMask |= capturedBit;
				else            _currentMask &= ~capturedBit;
				ApplyMask();
			};
			scroll.Controls.Add(cb);
			_ledItems.Add((cb, bit));

			col++;
			if (col >= 5) { col = 0; y += rowH; }
		}
		// Final row flush
		if (col > 0) y += rowH;
		y += 12;

		scroll.AutoScrollMinSize = new Size(0, y);
	}

	// ---- Apply / Sync ----

	private void ApplyMask()
	{
		if (lblMask != null)
			lblMask.Text = $"Mask: 0x{_currentMask:X8}";
		_scanner?.TestSetLeds(_currentMask);
	}

	private void SyncAndApply()
	{
		_syncing = true;
		foreach (var (cb, bit) in _ledItems)
			cb.Checked = (_currentMask & bit) != 0;
		_syncing = false;
		ApplyMask();
	}

	// ---- Helpers ----

	private static Button MakeBtn(string text, Point loc)
	{
		return new Button
		{
			Text      = text,
			Location  = loc,
			Size      = new Size(100, 30),
			BackColor = Color.FromArgb(45, 45, 60),
			ForeColor = Color.White,
			FlatStyle = FlatStyle.Flat,
			Cursor    = Cursors.Hand
		};
	}

	// Turn all LEDs off when window closes so scanner doesn't stay lit
	protected override void OnFormClosed(FormClosedEventArgs e)
	{
		_scanner?.TestSetLeds(DLL.IBSU_LED_NONE);
		base.OnFormClosed(e);
	}
}
