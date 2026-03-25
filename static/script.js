function fetchWithTimeout(url, timeoutMs = 2500) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    return fetch(url, {
        cache: "no-store",
        signal: controller.signal
    }).finally(() => {
        clearTimeout(timeoutId);
    });
}

async function fetchJson(url, timeoutMs = 2500) {
    const res = await fetchWithTimeout(url, timeoutMs);
    if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
    }
    return await res.json();
}

async function detectPublicIPv4() {
    try {
        const data = await fetchJson("https://api.ipify.org?format=json", 2500);
        return data.ip || null;
    } catch {
        return null;
    }
}

async function detectPublicIPv6() {
    try {
        const data = await fetchJson("https://api6.ipify.org?format=json", 1500);
        return data.ip || null;
    } catch {
        return null;
    }
}

function startScan() {
    document.getElementById("startScreen").style.display = "none";
    document.getElementById("scanTitle").style.display = "block";
    document.getElementById("status").style.display = "block";
    fakeScan(loadData);
}

function fakeScan(callback) {
    const status = document.getElementById("status");
    const steps = [
        "[ Verbindung wird hergestellt... ]",
        "[ IPv4 wird ermittelt... ]",
        "[ IPv6 wird ermittelt... ]",
        "[ System wird analysiert... ]",
        "[ Standort wird bestimmt... ]"
    ];

    let i = 0;

    const interval = setInterval(() => {
        status.textContent = steps[i];
        i += 1;

        if (i >= steps.length) {
            clearInterval(interval);
            callback();
        }
    }, 450);
}

async function loadData() {
    const status = document.getElementById("status");

    try {
        status.textContent = "[ IPv4 wird ermittelt... ]";
        const ipv4 = await detectPublicIPv4();

        status.textContent = "[ IPv6 wird ermittelt... ]";
        const ipv6 = await detectPublicIPv6();

        status.textContent = "[ Server wird abgefragt... ]";

        const params = new URLSearchParams();
        if (ipv4) params.set("client_ip_v4", ipv4);
        if (ipv6) params.set("client_ip_v6", ipv6);

        const query = params.toString();
        const data = await fetchJson(
            query ? `/api/info?${query}` : "/api/info",
            5000
        );

        document.getElementById("ip").textContent = data.ipv4 || "Unbekannt";
        document.getElementById("ipv6").textContent = data.ipv6 || "nicht vorhanden";
        document.getElementById("os").textContent = data.os || "Unbekannt";
        document.getElementById("browser").textContent = data.browser || "Unbekannt";
        document.getElementById("country").textContent = data.country || "Unbekannt";
        document.getElementById("city").textContent = data.city || "Unbekannt";

        document.getElementById("scanTitle").style.display = "none";
        status.textContent = "[ ANALYSE ABGESCHLOSSEN ]";
        document.getElementById("result").style.display = "block";
        document.getElementById("reloadBtn").style.display = "block";
    } catch (error) {
        console.error(error);
        status.textContent = "[ FEHLER BEI DER ANALYSE ]";
        document.getElementById("reloadBtn").style.display = "block";
    }
}

function reloadData() {
    document.getElementById("result").style.display = "none";
    document.getElementById("reloadBtn").style.display = "none";
    document.getElementById("scanTitle").style.display = "block";
    document.getElementById("status").style.display = "block";
    document.getElementById("status").textContent = "[ NEUSTART... ]";

    setTimeout(() => {
        fakeScan(loadData);
    }, 250);
}