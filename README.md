# Site Check Panel (Chrome extension)

## Install (1 minute)
1. Unzip this folder.
2. Open `chrome://extensions` and switch on **Developer mode** (top right).
3. Click **Load unpacked** and pick the unzipped `site-check-extension` folder.
4. Open any website, click the extension icon (pin it from the puzzle menu).

## Use
- The dashboard slides in over the same tab. Click the icon again, press Esc, click the dark area or the × to close it.
- On pages Chrome blocks scripts on (Web Store, PDF viewer) or sites whose security policy forbids it, it opens in a new tab instead.
- The left menu lists the 44 checks by name and description, grouped by category. Use the filter box or the arrow keys.
- Click a check, read what it does, press **Run check** to see the result.
- **Run all checks** runs everything (4 at a time). **Download PDF report** runs any checks you have not run yet, then saves a PDF with every result in tables.
- You can type another URL at the top and press **Load**.

## Notes
- Everything runs in your browser. The only data sent out is the hostname or URL, to the public services shown under each check.
- Open the dashboard from a tab that has already finished loading: Tech Stack, Trackers, Mixed Content, Linked Pages and Carbon Footprint then read the live page.
- TLS checks use Qualys SSL Labs; a first scan can take 1 to 3 minutes.
