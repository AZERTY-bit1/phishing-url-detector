# 🎣 Phishing URL Detector

![tests](https://github.com/AZERTY-bit1/phishing-url-detector/actions/workflows/tests.yml/badge.svg)
![python](https://img.shields.io/badge/python-3.8%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

Gives a **risk score** to a link before you click it, and explains *why*. Works fully offline: the URL is never opened.

## ✨ Features

- Raw IP hosts and the `user@host` trick
- Look-alike brands (`paypa1`, `g00gle`...) on the wrong domain
- Suspicious TLDs (`.xyz`, `.zip`, `.tk`...) and URL shorteners
- Punycode, too many subdomains / hyphens, very long URLs
- Sensitive keywords (`login`, `verify`, `password`...)

## 🚀 Usage

No installation needed - only Python 3.8+.

```bash
git clone https://github.com/AZERTY-bit1/phishing-url-detector.git
cd phishing-url-detector
python phishing_detector.py "http://paypa1-secure-login.xyz/verify" https://github.com
python phishing_detector.py -f urls.txt
```

## 📸 Example output

```
DANGEROUS      score=9   http://paypa1-secure-login.xyz/verify
   +1 not using HTTPS
   +2 suspicious TLD .xyz
   +3 mentions 'paypal' but real domain is 'paypa1-secure-login.xyz'
   +3 sensitive keywords: login, secure, verify

PROBABLY SAFE  score=0   https://github.com
```

## 🧪 Tests

```bash
python -m unittest discover -s tests -v
```

## ⚠️ Disclaimer

This is a **defensive / educational** tool. Only use it on systems and data you own or are allowed to check.

## 📄 License

MIT - see [LICENSE](LICENSE).
