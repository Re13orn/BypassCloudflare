package dev.burp.cfbypass;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;
import java.time.LocalTime;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CfBypassExtension implements BurpExtension {

    private MontoyaApi api;
    private volatile boolean rewriteEnabled = true;
    private volatile boolean normalizeEnabled = true;
    private final List<String> hostRules = new CopyOnWriteArrayList<>();
    private volatile boolean cfproxyRunning = false;
    private volatile int currentPort;
    private volatile String currentProfile = "chrome_131";

    private JLabel overallBadge;
    private JLabel cfproxyDot;
    private JLabel cfproxyValue;
    private JLabel rewriteDot;
    private JLabel rewriteValue;
    private JLabel stateDot;
    private JLabel stateValue;
    private JTextField portField;
    private JLabel hostsSummary;
    private JTextArea logArea;
    private ProxyManager proxyManager;
    private Timer autoRefreshTimer;

    private static final String PROXY_HOST = "127.0.0.1";
    private static final int DEFAULT_PORT = 8888;
    private static final String CONFIG_HEADER = "X-Cfproxy-Config";
    private static final String PREF_PORT = "cfproxy.port";
    private static final String PREF_FILTER = "cfproxy.filter";
    private static final String PREF_REWRITE = "cfproxy.rewrite";
    private static final String PREF_PROFILE = "cfproxy.profile";
    private static final String[] PROFILES = {
            "random",
            "chrome_131", "chrome_133", "chrome_144", "chrome_146", "chrome_150", "chrome_152",
            "firefox_132", "firefox_135", "firefox_148",
            "safari_16_0", "safari_ios_17_0", "safari_ios_18_0",
            "opera_91", "okhttp4_android_12",
    };
    private static final Pattern CHROME_UA = Pattern.compile("Chrome/(\\d+)");

    private static final Color GREEN = new Color(0x1A7F37);
    private static final Color RED = new Color(0xCF222E);
    private static final Color ORANGE = new Color(0x9A6700);
    private static final Color GRAY = new Color(0x6E7781);
    private static final Color BORDER = new Color(0xD0D7DE);
    private static final Color MUTED = new Color(0x57606A);

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("CF Bypass");

        var prefs = api.persistence().preferences();
        int port = DEFAULT_PORT;
        Integer savedPort = prefs.getInteger(PREF_PORT);
        if (savedPort != null && savedPort > 0 && savedPort <= 65535) {
            port = savedPort;
        }
        currentPort = port;
        String savedFilter = prefs.getString(PREF_FILTER);
        if (savedFilter != null && !savedFilter.isBlank()) {
            for (String d : savedFilter.split(",")) {
                if (!d.isBlank()) {
                    hostRules.add(d.trim().toLowerCase());
                }
            }
        }
        Boolean savedRewrite = prefs.getBoolean(PREF_REWRITE);
        if (savedRewrite != null) {
            rewriteEnabled = savedRewrite;
        }
        String savedProfile = prefs.getString(PREF_PROFILE);
        if (savedProfile != null && !savedProfile.isEmpty()) {
            currentProfile = savedProfile;
        }

        api.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
                return RequestToBeSentAction.continueWith(process(request));
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
                return ResponseReceivedAction.continueWith(response);
            }
        });

        proxyManager = new ProxyManager(port, this::log);
        proxyManager.setPortListener(p -> {
            prefs.setInteger(PREF_PORT, p);
            currentPort = p;
            SwingUtilities.invokeLater(() -> {
                if (portField != null) {
                    portField.setText(String.valueOf(p));
                }
            });
        });

        api.userInterface().registerSuiteTab("CF Bypass", buildPanel());

        autoRefreshTimer = new Timer(4000, e -> refreshStatus());
        autoRefreshTimer.start();

        api.extension().registerUnloadingHandler(() -> {
            autoRefreshTimer.stop();
            proxyManager.stop();
        });
        Runtime.getRuntime().addShutdownHook(new Thread(proxyManager::stop));

        log("extension loaded (zero-config mode)");
        new Thread(() -> {
            proxyManager.start();
            refreshStatus();
        }, "cfproxy-autostart").start();
    }

    // ---------- request rewriting (zero-config) ----------

    private HttpRequest process(HttpRequestToBeSent request) {
        if (!rewriteEnabled) {
            return request;
        }
        HttpService svc = request.httpService();
        // never rewrite a request that already targets cfproxy (avoid loops)
        if (PROXY_HOST.equals(svc.host()) && svc.port() == currentPort) {
            return request;
        }
        String host = svc.host();
        if (!shouldRewrite(host)) {
            return request;
        }

        String scheme = svc.secure() ? "https" : "http";
        int port = svc.port();
        // omit the default port: browsers send Host without :443/:80
        boolean defaultPort = (svc.secure() && port == 443) || (!svc.secure() && port == 80);
        String hostHeader = defaultPort ? host : host + ":" + port;
        StringBuilder order = new StringBuilder();
        for (var h : request.headers()) {
            if (order.length() > 0) {
                order.append(",");
            }
            order.append(h.name());
        }
        String config = "{\"host\":\"" + hostHeader
                + "\",\"scheme\":\"" + scheme + "\",\"order\":\"" + order + "\",\"profile\":\"" + currentProfile + "\"}";
        HttpService local = HttpService.httpService(PROXY_HOST, currentPort, false);
        HttpRequest modified = request.withService(local).withAddedHeader(CONFIG_HEADER, config);
        if (normalizeEnabled) {
            modified = normalize(modified);
        }
        log("rewrite " + scheme + "://" + host + request.path());
        return modified;
    }

    private boolean shouldRewrite(String host) {
        if (hostRules.isEmpty()) {
            return true;
        }
        String h = host.toLowerCase();
        for (String d : hostRules) {
            if (h.equals(d) || h.endsWith("." + d)) {
                return true;
            }
        }
        return false;
    }

    // ---------- UI ----------

    private String guideText() {
        return String.join("\n",
            "Zero configuration. The extension rewrites each request's destination",
            "to the local cfproxy and passes the real target in a header, so there",
            "is NO upstream proxy to set and NO CA to import (Burp talks plain HTTP",
            "to cfproxy on localhost). Works for Proxy, Repeater, Intruder, Scanner.",
            "",
            "If you added an upstream proxy rule for an older version, remove it:",
            "  Settings -> Network -> Connections -> Upstream proxy servers.",
            "",
            "Hosts filter: blank = spoof every host; or comma-separated domains",
            "(e.g. crypto.com,example.com) to spoof only those (incl. subdomains).",
            "",
            "cfproxy re-sends each request with a Chrome TLS (JA3/JA4) + HTTP/2",
            "fingerprint via uTLS. Watch the Activity log to see rewrites.");
    }

    private JPanel buildPanel() {
        JPanel root = new JPanel(new BorderLayout(0, 12));
        root.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        JPanel north = new JPanel();
        north.setLayout(new BoxLayout(north, BoxLayout.Y_AXIS));
        north.setOpaque(false);
        north.add(buildHeader());
        north.add(Box.createVerticalStrut(12));
        north.add(buildStatusCard());
        north.add(Box.createVerticalStrut(12));
        north.add(buildControls());
        root.add(north, BorderLayout.NORTH);

        root.add(buildLogCard(), BorderLayout.CENTER);
        root.add(buildFooter(), BorderLayout.SOUTH);
        return root;
    }

    private JPanel buildHeader() {
        JPanel header = new JPanel(new BorderLayout());
        header.setOpaque(false);
        JPanel titleBox = new JPanel();
        titleBox.setLayout(new BoxLayout(titleBox, BoxLayout.Y_AXIS));
        titleBox.setOpaque(false);
        JLabel title = new JLabel("CF Bypass");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 20f));
        JLabel subtitle = new JLabel("Chrome TLS & HTTP/2 fingerprint for Burp traffic");
        subtitle.setForeground(MUTED);
        titleBox.add(title);
        titleBox.add(Box.createVerticalStrut(2));
        titleBox.add(subtitle);

        overallBadge = new JLabel("Checking");
        overallBadge.setOpaque(true);
        overallBadge.setBorder(BorderFactory.createEmptyBorder(4, 12, 4, 12));
        overallBadge.setFont(overallBadge.getFont().deriveFont(Font.BOLD, 12f));
        styleBadge(GRAY, new Color(0xEAEEF2));

        header.add(titleBox, BorderLayout.WEST);
        header.add(overallBadge, BorderLayout.EAST);
        return header;
    }

    private JPanel buildStatusCard() {
        JPanel card = card();
        cfproxyDot = dot();
        cfproxyValue = value("Checking...");
        rewriteDot = dot();
        rewriteValue = value(rewriteText());
        rewriteDot.setForeground(rewriteEnabled ? GREEN : GRAY);
        stateDot = dot();
        stateDot.setForeground(normalizeEnabled ? GREEN : GRAY);
        stateValue = value(normalizeEnabled ? "On" : "Off");

        GridBagConstraints gc = new GridBagConstraints();
        gc.anchor = GridBagConstraints.WEST;
        gc.insets = new Insets(4, 4, 4, 4);
        int r = 0;
        r = statusRow(card, gc, r, cfproxyDot, "cfproxy", cfproxyValue);
        r = statusRow(card, gc, r, rewriteDot, "Rewrite", rewriteValue);
        r = statusRow(card, gc, r, stateDot, "Header normalization", stateValue);
        return card;
    }

    private int statusRow(JPanel card, GridBagConstraints gc, int row,
                          JLabel dot, String name, JLabel value) {
        gc.gridx = 0; gc.gridy = row; gc.weightx = 0;
        card.add(dot, gc);
        gc.gridx = 1;
        JLabel nameLabel = new JLabel(name);
        nameLabel.setPreferredSize(new Dimension(170, nameLabel.getPreferredSize().height));
        card.add(nameLabel, gc);
        gc.gridx = 2; gc.weightx = 1;
        card.add(value, gc);
        return row + 1;
    }

    private JPanel buildControls() {
        JPanel wrap = new JPanel();
        wrap.setLayout(new BoxLayout(wrap, BoxLayout.Y_AXIS));
        wrap.setOpaque(false);

        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        row1.setOpaque(false);
        JCheckBox rewriteBox = new JCheckBox("Enable rewrite", rewriteEnabled);
        rewriteBox.addActionListener(e -> {
            rewriteEnabled = rewriteBox.isSelected();
            api.persistence().preferences().setBoolean(PREF_REWRITE, rewriteEnabled);
            updateRewriteState();
            log("rewrite " + (rewriteEnabled ? "enabled" : "disabled"));
        });
        JCheckBox normalizeBox = new JCheckBox("Normalize headers", normalizeEnabled);
        normalizeBox.addActionListener(e -> {
            normalizeEnabled = normalizeBox.isSelected();
            stateValue.setText(normalizeEnabled ? "On" : "Off");
            stateDot.setForeground(normalizeEnabled ? GREEN : GRAY);
        });
        JButton restartBtn = new JButton("Restart proxy");
        restartBtn.addActionListener(e -> new Thread(() -> {
            proxyManager.restart();
            refreshStatus();
        }, "cfproxy-restart").start());
        row1.add(rewriteBox);
        row1.add(normalizeBox);
        row1.add(Box.createHorizontalStrut(16));
        row1.add(restartBtn);

        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        row2.setOpaque(false);
        row2.add(new JLabel("Port"));
        portField = new JTextField(String.valueOf(currentPort), 5);
        row2.add(portField);
        JButton applyPortBtn = new JButton("Apply");
        applyPortBtn.addActionListener(e -> applyPort());
        row2.add(applyPortBtn);
        row2.add(Box.createHorizontalStrut(16));
        row2.add(new JLabel("Hosts"));
        hostsSummary = new JLabel(hostsSummaryText());
        hostsSummary.setForeground(MUTED);
        row2.add(hostsSummary);
        JButton manageHostsBtn = new JButton("Manage");
        manageHostsBtn.addActionListener(e -> openHostsManager());
        row2.add(manageHostsBtn);
        row2.add(Box.createHorizontalStrut(16));
        row2.add(new JLabel("Profile"));
        JComboBox<String> profileCombo = new JComboBox<>(PROFILES);
        profileCombo.setSelectedItem(currentProfile);
        profileCombo.setToolTipText("fixed fingerprint, or random to rotate desktop Chrome per request");
        profileCombo.addActionListener(e -> {
            currentProfile = (String) profileCombo.getSelectedItem();
            api.persistence().preferences().setString(PREF_PROFILE, currentProfile);
            log("impersonation profile: " + currentProfile);
        });
        row2.add(profileCombo);

        wrap.add(row1);
        wrap.add(Box.createVerticalStrut(8));
        wrap.add(row2);
        return wrap;
    }

    private JPanel buildLogCard() {
        JPanel card = card();
        card.setLayout(new BorderLayout(0, 8));
        JPanel bar = new JPanel(new BorderLayout());
        bar.setOpaque(false);
        JLabel title = new JLabel("Activity");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 13f));
        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> logArea.setText(""));
        bar.add(title, BorderLayout.WEST);
        bar.add(clearBtn, BorderLayout.EAST);

        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        logArea.setLineWrap(true);
        logArea.setWrapStyleWord(true);
        JScrollPane scroll = new JScrollPane(logArea);
        scroll.setBorder(BorderFactory.createLineBorder(BORDER, 1, true));
        card.add(bar, BorderLayout.NORTH);
        card.add(scroll, BorderLayout.CENTER);
        return card;
    }

    private JPanel buildFooter() {
        JPanel footer = new JPanel(new BorderLayout());
        footer.setOpaque(false);
        JButton guideBtn = new JButton("Setup guide");
        guideBtn.addActionListener(e -> showGuide());
        JLabel hint = new JLabel("Zero-config: no upstream proxy, no CA import");
        hint.setForeground(MUTED);
        hint.setFont(hint.getFont().deriveFont(11f));
        footer.add(guideBtn, BorderLayout.WEST);
        footer.add(hint, BorderLayout.EAST);
        return footer;
    }

    // ---------- small UI helpers ----------

    private JPanel card() {
        JPanel p = new JPanel(new GridBagLayout());
        Border inner = BorderFactory.createEmptyBorder(10, 12, 10, 12);
        p.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(BORDER, 1, true), inner));
        return p;
    }

    private JLabel dot() {
        JLabel l = new JLabel("\u25CF");
        l.setForeground(GRAY);
        l.setFont(l.getFont().deriveFont(16f));
        return l;
    }

    private JLabel value(String text) {
        JLabel l = new JLabel(text);
        l.setForeground(MUTED);
        return l;
    }

    private void styleBadge(Color fg, Color bg) {
        overallBadge.setForeground(fg);
        overallBadge.setBackground(bg);
    }

    private String rewriteText() {
        if (!rewriteEnabled) {
            return "Disabled";
        }
        return hostRules.isEmpty() ? "Enabled - all hosts" : "Enabled - " + hostRules.size() + " hosts";
    }

    private void updateRewriteState() {
        rewriteValue.setText(rewriteText());
        rewriteDot.setForeground(rewriteEnabled ? GREEN : GRAY);
        updateOverall();
    }

    private void updateOverall() {
        SwingUtilities.invokeLater(() -> {
            boolean ready = cfproxyRunning && rewriteEnabled;
            overallBadge.setText(ready ? "Ready" : "Not ready");
            styleBadge(ready ? GREEN : ORANGE, ready ? new Color(0xDAFBE1) : new Color(0xFFF8C5));
        });
    }

    // ---------- logic ----------

    private void applyPort() {
        final int p;
        try {
            p = Integer.parseInt(portField.getText().trim());
        } catch (NumberFormatException e) {
            log("invalid port: " + portField.getText());
            return;
        }
        if (p < 1 || p > 65535) {
            log("port out of range: " + p);
            return;
        }
        api.persistence().preferences().setInteger(PREF_PORT, p);
        currentPort = p;
        proxyManager.setPort(p);
        log("port set to " + p + "; restarting cfproxy");
        new Thread(() -> {
            proxyManager.restart();
            refreshStatus();
        }, "cfproxy-applyport").start();
    }

    private String hostsSummaryText() {
        return hostRules.isEmpty() ? "all" : hostRules.size() + " rule(s)";
    }

    private void openHostsManager() {
        buildHostsDialog().setVisible(true);
    }

    JDialog buildHostsDialog() {
        JDialog dialog = new JDialog((Frame) null, "Spoofed hosts", true);
        JPanel content = new JPanel(new BorderLayout(8, 8));
        content.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        DefaultListModel<String> model = new DefaultListModel<>();
        for (String d : hostRules) {
            model.addElement(d);
        }
        JList<String> list = new JList<>(model);
        list.setVisibleRowCount(8);
        content.add(new JScrollPane(list), BorderLayout.CENTER);

        JPanel top = new JPanel(new BorderLayout(6, 0));
        JTextField input = new JTextField();
        input.setToolTipText("domain, e.g. crypto.com - also matches subdomains");
        JButton addBtn = new JButton("Add");
        top.add(input, BorderLayout.CENTER);
        top.add(addBtn, BorderLayout.EAST);
        content.add(top, BorderLayout.NORTH);

        JPanel bottom = new JPanel(new BorderLayout());
        JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        JButton removeBtn = new JButton("Remove");
        JButton clearBtn = new JButton("Clear all");
        btns.add(removeBtn);
        btns.add(clearBtn);
        bottom.add(btns, BorderLayout.WEST);
        JLabel hint = new JLabel("empty = all hosts");
        hint.setForeground(MUTED);
        bottom.add(hint, BorderLayout.EAST);
        content.add(bottom, BorderLayout.SOUTH);

        Runnable add = () -> {
            String v = input.getText().trim().toLowerCase();
            if (v.isEmpty()) {
                return;
            }
            if (!model.contains(v)) {
                model.addElement(v);
            }
            input.setText("");
            input.requestFocus();
            syncHosts(model);
        };
        addBtn.addActionListener(e -> add.run());
        input.addActionListener(e -> add.run());
        removeBtn.addActionListener(e -> {
            for (String v : list.getSelectedValuesList()) {
                model.removeElement(v);
            }
            syncHosts(model);
        });
        clearBtn.addActionListener(e -> {
            model.clear();
            syncHosts(model);
        });

        dialog.setContentPane(content);
        dialog.setSize(440, 330);
        dialog.setLocationRelativeTo(null);
        return dialog;
    }

    private void syncHosts(DefaultListModel<String> model) {
        hostRules.clear();
        for (int i = 0; i < model.size(); i++) {
            hostRules.add(model.get(i));
        }
        api.persistence().preferences().setString(PREF_FILTER, String.join(",", hostRules));
        hostsSummary.setText(hostsSummaryText());
        updateRewriteState();
        log("hosts filter: " + (hostRules.isEmpty() ? "(all hosts)" : String.join(",", hostRules)));
    }

    private void refreshStatus() {
        new Thread(() -> {
            final boolean ok = proxyManager.isRunning();
            final int p = proxyManager.getPort();
            cfproxyRunning = ok;
            SwingUtilities.invokeLater(() -> {
                cfproxyValue.setText(ok ? "Running on " + PROXY_HOST + ":" + p : "Not running");
                cfproxyValue.setForeground(ok ? Color.BLACK : RED);
                cfproxyDot.setForeground(ok ? GREEN : RED);
                updateOverall();
            });
        }, "cfproxy-status").start();
    }

    private void showGuide() {
        SwingUtilities.invokeLater(() ->
                JOptionPane.showMessageDialog(null, guideText(),
                        "CF Bypass - guide", JOptionPane.INFORMATION_MESSAGE));
    }

    private void log(String msg) {
        if (logArea != null) {
            SwingUtilities.invokeLater(() -> {
                logArea.append("[" + LocalTime.now().withNano(0) + "] " + msg + "\n");
                logArea.setCaretPosition(logArea.getDocument().getLength());
            });
        }
    }

    // ---------- HTTP normalization ----------

    private HttpRequest normalize(HttpRequest request) {
        String ua = request.headerValue("User-Agent");
        if (ua == null) {
            return request;
        }
        HttpRequest out = request;
        for (String h : new String[]{"Proxy-Connection", "Proxy-Authorization"}) {
            if (request.headerValue(h) != null) {
                out = out.withRemovedHeader(h);
            }
        }
        Matcher m = CHROME_UA.matcher(ua);
        if (m.find()) {
            String ver = m.group(1);
            String brand = "\"Not?A_Brand\";v=\"99\", \"Chromium\";v=\"" + ver
                    + "\", \"Google Chrome\";v=\"" + ver + "\"";
            String cur = request.headerValue("sec-ch-ua");
            if (cur != null && !brand.equals(cur)) {
                out = out.withUpdatedHeader("sec-ch-ua", brand);
            }
            String mobile = request.headerValue("sec-ch-ua-mobile");
            if (mobile != null && !"?0".equals(mobile)) {
                out = out.withUpdatedHeader("sec-ch-ua-mobile", "?0");
            }
        }
        return out;
    }
}
