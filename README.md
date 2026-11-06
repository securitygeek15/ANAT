# ANAT — AI Network Anomaly Tracker

ANAT is a small network-monitoring app. It captures packets, shows them in a web dashboard, and creates alerts for selected suspicious connection attempts.

## What you need

- Windows, Python 3.10 or newer, and this project
- [Npcap](https://npcap.com/#download) for packet capture on Windows
- Permission to monitor the network you use

When installing Npcap, leave **Restrict Npcap driver access to Administrators only** unchecked. The Npcap installer needs Windows Administrator approval, but you can then run ANAT from a normal PowerShell window.

## Install and start (Windows)

Install Npcap, then open PowerShell and download the project:

```powershell
git clone https://github.com/securitygeek15/ANAT.git
cd ANAT
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Keep the PowerShell window open while you use ANAT. Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

If PowerShell says script execution is disabled, use the app's Python directly instead:

```powershell
.\venv\Scripts\python.exe app.py
```

The dashboard shows whether packet capture is running. If capture is unavailable, check that Npcap is installed and restart ANAT.

## Using the dashboard

- **Overview** shows packet totals, alert counts, and recent activity.
- **Packets** shows captured traffic. Use the filters to find packets, or choose **Export CSV**.
- **Alerts** shows detections. Use the filters or choose **Export CSV**.

ANAT automatically ignores packets **sourced by your default gateway**. They are not saved or shown. Other traffic, including packets sent to the gateway, remains visible.

## What creates an alert?

ANAT only checks initial inbound TCP connection attempts to this computer. Normal outbound browsing and large packets by themselves do not create alerts.

- **Port scan:** one source attempts more than 10 different ports on this computer within 60 seconds.
- **Sensitive port:** an inbound attempt targets a configured port such as SSH (22).
- **SYN flood:** one source makes more than 100 initial connection attempts per second to the same port.

An alert means a connection attempt met a detection rule; it does not prove that the attempt succeeded or that the computer was compromised.

## Testing

To run the automated tests, open another PowerShell in the project folder and run:

```powershell
.\venv\Scripts\python.exe -m unittest discover -s tests -v
```

To check live capture, use a second computer on a network you own or are authorized to test. Try connecting from that computer to several different ports on the ANAT computer, then check **Alerts** for a port-scan detection. A single attempt to a sensitive port can also create an alert. The other computer is needed because ANAT checks inbound connection attempts, not your own outbound connections.

## Linux and macOS

Clone the project, create and activate a virtual environment, and install the requirements. Then run `sudo -E ./venv/bin/python app.py` to enable packet capture. Open [http://127.0.0.1:5000](http://127.0.0.1:5000).

## Legal

Use ANAT only on networks you own or have permission to monitor. Packet capture may be restricted by local laws.

## License

MIT. See [LICENSE](./LICENSE).
