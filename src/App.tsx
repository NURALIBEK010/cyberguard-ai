
import {
  useEffect,
  useMemo,
  useState,
  type CSSProperties,
  type FormEvent,
  type ReactNode,
} from "react";

import "./App.css";

import {
  apiGet,
  apiPatch,
  apiPost,
  clearSession,
} from "./api";

type Language = "UZ" | "RU" | "EN";

type Page =
  | "dashboard"
  | "security"
  | "scan"
  | "devices"
  | "threats"
  | "password"
  | "network"
  | "reports"
  | "ai"
  | "logs"
  | "notifications"
  | "news"
  | "profile"
  | "settings"
  | "help";

type User = {
  id?: string | number;
  name: string;
  email: string;
  role?: string;
  createdAt?: string;
};

type Device = {
  id: number;
  name: string;
  type: string;
  ip: string;
  status: string;
  risk: string;
  last_seen?: string;
  created_at?: string;
};

type Threat = {
  id: number;
  name: string;
  type: string;
  device: string;
  severity: string;
  status: string;
  time: string;
  score?: number;
  description?: string;
  evidence?: string;
};

type Notification = {
  id: number;
  title: string;
  message: string;
  time: string;
  unread: boolean;
  type: "success" | "warning" | "danger" | "info";
  channel?: string;
};

type LogItem = {
  id: number;
  action: string;
  description: string;
  time: string;
  type: "success" | "warning" | "danger" | "info";
};

type PasswordPolicy = {
  minLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumber: boolean;
  requireSpecial: boolean;
};

type DashboardResponse = {
  success: boolean;
  securityScore?: number;
  activeThreats?: number;
  devices?: Array<{
    id: number;
    name: string;
    type: string;
    ip: string;
    status: string;
    risk: string;
    last_seen?: string;
    created_at?: string;
  }>;
  threats?: Array<{
    id: number;
    name: string;
    type: string;
    device_name?: string;
    severity: string;
    status: string;
    score?: number;
    description?: string;
    evidence?: string;
    detected_at?: string;
  }>;
};

type AIResponse = {
  success: boolean;
  answer?: string;
  securityScore?: number;
  message?: string;
};

const translations = {
  UZ: {
    dashboard: "Boshqaruv paneli",
    security: "Xavfsizlik markazi",
    scan: "Tizim skaneri",
    devices: "Qurilmalar",
    threats: "Tahdidlar",
    password: "Parol xavfsizligi",
    network: "Tarmoq monitoringi",
    reports: "Xavfsizlik hisobotlari",
    ai: "AI xavfsizlik",
    logs: "Xavfsizlik jurnali",
    notifications: "Bildirishnomalar",
    news: "Kiber yangiliklar",
    profile: "Profil",
    settings: "Sozlamalar",
    help: "Yordam",
    main: "ASOSIY",
    securityGroup: "XAVFSIZLIK",
    analytics: "ANALITIKA",
    account: "HISOB",
    overview: "Umumiy ko‘rinish",
    securityScore: "Xavfsizlik darajasi",
    protected: "Himoyalangan",
    threatsFound: "Aniqlangan tahdidlar",
    devicesCount: "Qurilmalar",
    networkStatus: "Tarmoq holati",
    recentActivity: "So‘nggi faollik",
    activity: "Faollik",
    quickActions: "Tezkor amallar",
    startScan: "Skanerlashni boshlash",
    scanNow: "Hozir skanerlash",
    viewAll: "Barchasini ko‘rish",
    online: "Onlayn",
    offline: "Oflayn",
    low: "Past",
    medium: "O‘rta",
    high: "Yuqori",
    critical: "Kritik",
    blocked: "Bloklangan",
    active: "Faol",
    search: "Qidirish...",
    refresh: "Yangilash",
    add: "Qo‘shish",
    delete: "O‘chirish",
    save: "Saqlash",
    cancel: "Bekor qilish",
    analyze: "Tahlil qilish",
    generate: "Generatsiya qilish",
    download: "Yuklab olish",
    login: "Kirish",
    register: "Ro‘yxatdan o‘tish",
    email: "Email",
    passwordLabel: "Parol",
    name: "Ism",
    welcome: "CyberGuard AI tizimiga xush kelibsiz",
    loginDescription: "Kiberxavfsizlikni aqlli boshqaring.",
    noAccount: "Hisobingiz yo‘qmi?",
    haveAccount: "Hisobingiz bormi?",
    createAccount: "Hisob yaratish",
    signIn: "Tizimga kirish",
    logout: "Chiqish",
    darkMode: "Tungi rejim",
    lightMode: "Yorug‘ rejim",
    systemScanner: "Tizim skaneri",
    scanDescription: "Qurilmangizni tahdidlar uchun tekshiring.",
    scanning: "Skanerlanmoqda...",
    scanComplete: "Skanerlash yakunlandi.",
    scanDescriptionLong:
      "Skanerlash tizimdagi zararli fayllar, zaifliklar va shubhali jarayonlarni aniqlash uchun security engine bilan ishlaydi.",
    deviceName: "Qurilma",
    ipAddress: "IP manzil",
    status: "Holat",
    risk: "Xavf",
    type: "Tur",
    threatName: "Tahdid nomi",
    severity: "Jiddiylik",
    time: "Vaqt",
    action: "Amal",
    block: "Bloklash",
    blockedMessage: "Tahdid bloklandi.",
    passwordSecurity: "Parol xavfsizligi",
    passwordPlaceholder: "Parolni kiriting",
    weak: "Zaif",
    fair: "O‘rtacha",
    strong: "Kuchli",
    excellent: "Juda kuchli",
    passwordTips: "Parol bo‘yicha tavsiyalar",
    passwordTip1: "Kamida 12 ta belgidan foydalaning.",
    passwordTip2: "Katta va kichik harflarni aralashtiring.",
    passwordTip3: "Raqam va maxsus belgilar qo‘shing.",
    passwordTip4: "Shaxsiy ma’lumotlardan foydalanmang.",
    networkMonitor: "Tarmoq monitoringi",
    secure: "Xavfsiz",
    reportsTitle: "Xavfsizlik hisobotlari",
    reportDescription: "Tizim xavfsizligi bo‘yicha hisobot yarating.",
    generateReport: "Hisobot yaratish",
    aiTitle: "AI xavfsizlik yordamchisi",
    aiPlaceholder: "Savolingizni yozing...",
    aiWelcome:
      "Salom! Men CyberGuard AI yordamchisiman. Men tizim holatingiz, tahdidlar va kiberxavfsizlik savollarini tahlil qilishga yordam beraman.",
    logsTitle: "Xavfsizlik jurnali",
    notificationsTitle: "Bildirishnomalar",
    newsTitle: "Kiber yangiliklar",
    profileTitle: "Profil",
    settingsTitle: "Sozlamalar",
    helpTitle: "Yordam markazi",
    language: "Til",
    theme: "Mavzu",
    accountSecurity: "Hisob xavfsizligi",
    twoFactor: "Ikki bosqichli autentifikatsiya",
    enabled: "Yoqilgan",
    disabled: "O‘chirilgan",
    helpText:
      "CyberGuard AI bo‘yicha yordam kerak bo‘lsa, quyidagi bo‘limlardan foydalaning.",
    serverError: "Server bilan bog‘lanishda xatolik.",
    invalidLogin: "Email yoki parol noto‘g‘ri.",
    registered: "Ro‘yxatdan o‘tish muvaffaqiyatli.",
    loggedIn: "Tizimga muvaffaqiyatli kirdingiz.",
    reportGenerated: "Hisobot ma’lumotlari muvaffaqiyatli olindi.",
  },

  RU: {
    dashboard: "Панель управления",
    security: "Центр безопасности",
    scan: "Сканер системы",
    devices: "Устройства",
    threats: "Угрозы",
    password: "Безопасность пароля",
    network: "Мониторинг сети",
    reports: "Отчёты безопасности",
    ai: "AI безопасность",
    logs: "Журнал безопасности",
    notifications: "Уведомления",
    news: "Киберновости",
    profile: "Профиль",
    settings: "Настройки",
    help: "Помощь",
    main: "ГЛАВНОЕ",
    securityGroup: "БЕЗОПАСНОСТЬ",
    analytics: "АНАЛИТИКА",
    account: "АККАУНТ",
    overview: "Обзор",
    securityScore: "Уровень безопасности",
    protected: "Защищено",
    threatsFound: "Обнаруженные угрозы",
    devicesCount: "Устройства",
    networkStatus: "Состояние сети",
    recentActivity: "Последняя активность",
    activity: "Активность",
    quickActions: "Быстрые действия",
    startScan: "Начать сканирование",
    scanNow: "Сканировать",
    viewAll: "Посмотреть все",
    online: "Онлайн",
    offline: "Офлайн",
    low: "Низкий",
    medium: "Средний",
    high: "Высокий",
    critical: "Критический",
    blocked: "Заблокировано",
    active: "Активна",
    search: "Поиск...",
    refresh: "Обновить",
    add: "Добавить",
    delete: "Удалить",
    save: "Сохранить",
    cancel: "Отмена",
    analyze: "Анализировать",
    generate: "Создать",
    download: "Скачать",
    login: "Войти",
    register: "Регистрация",
    email: "Email",
    passwordLabel: "Пароль",
    name: "Имя",
    welcome: "Добро пожаловать в CyberGuard AI",
    loginDescription: "Управляйте кибербезопасностью интеллектуально.",
    noAccount: "Нет аккаунта?",
    haveAccount: "Уже есть аккаунт?",
    createAccount: "Создать аккаунт",
    signIn: "Войти в систему",
    logout: "Выйти",
    darkMode: "Тёмная тема",
    lightMode: "Светлая тема",
    systemScanner: "Сканер системы",
    scanDescription: "Проверьте устройство на наличие угроз.",
    scanning: "Сканирование...",
    scanComplete: "Сканирование завершено.",
    scanDescriptionLong:
      "Сканирование работает через security engine и анализирует доступные сигналы безопасности.",
    deviceName: "Устройство",
    ipAddress: "IP адрес",
    status: "Статус",
    risk: "Риск",
    type: "Тип",
    threatName: "Название угрозы",
    severity: "Серьёзность",
    time: "Время",
    action: "Действие",
    block: "Заблокировать",
    blockedMessage: "Угроза заблокирована.",
    passwordSecurity: "Безопасность пароля",
    passwordPlaceholder: "Введите пароль",
    weak: "Слабый",
    fair: "Средний",
    strong: "Сильный",
    excellent: "Очень сильный",
    passwordTips: "Советы по паролю",
    passwordTip1: "Используйте минимум 12 символов.",
    passwordTip2: "Смешивайте прописные и строчные буквы.",
    passwordTip3: "Добавляйте цифры и специальные символы.",
    passwordTip4: "Не используйте личную информацию.",
    networkMonitor: "Мониторинг сети",
    secure: "Безопасно",
    reportsTitle: "Отчёты безопасности",
    reportDescription: "Создайте отчёт о безопасности системы.",
    generateReport: "Создать отчёт",
    aiTitle: "AI помощник безопасности",
    aiPlaceholder: "Введите вопрос...",
    aiWelcome:
      "Здравствуйте! Я CyberGuard AI. Я могу анализировать состояние безопасности и отвечать на вопросы.",
    logsTitle: "Журнал безопасности",
    notificationsTitle: "Уведомления",
    newsTitle: "Киберновости",
    profileTitle: "Профиль",
    settingsTitle: "Настройки",
    helpTitle: "Центр помощи",
    language: "Язык",
    theme: "Тема",
    accountSecurity: "Безопасность аккаунта",
    twoFactor: "Двухфакторная аутентификация",
    enabled: "Включено",
    disabled: "Выключено",
    helpText:
      "Используйте разделы ниже для получения помощи по CyberGuard AI.",
    serverError: "Ошибка подключения к серверу.",
    invalidLogin: "Неверный email или пароль.",
    registered: "Регистрация прошла успешно.",
    loggedIn: "Вы успешно вошли.",
    reportGenerated: "Данные отчёта успешно получены.",
  },

  EN: {
    dashboard: "Dashboard",
    security: "Security Center",
    scan: "System Scanner",
    devices: "Devices",
    threats: "Threats",
    password: "Password Security",
    network: "Network Monitor",
    reports: "Security Reports",
    ai: "AI Security",
    logs: "Security Logs",
    notifications: "Notifications",
    news: "Cyber News",
    profile: "Profile",
    settings: "Settings",
    help: "Help",
    main: "MAIN",
    securityGroup: "SECURITY",
    analytics: "ANALYTICS",
    account: "ACCOUNT",
    overview: "Overview",
    securityScore: "Security Score",
    protected: "Protected",
    threatsFound: "Threats Found",
    devicesCount: "Devices",
    networkStatus: "Network Status",
    recentActivity: "Recent Activity",
    activity: "Activity",
    quickActions: "Quick Actions",
    startScan: "Start Scan",
    scanNow: "Scan Now",
    viewAll: "View All",
    online: "Online",
    offline: "Offline",
    low: "Low",
    medium: "Medium",
    high: "High",
    critical: "Critical",
    blocked: "Blocked",
    active: "Active",
    search: "Search...",
    refresh: "Refresh",
    add: "Add",
    delete: "Delete",
    save: "Save",
    cancel: "Cancel",
    analyze: "Analyze",
    generate: "Generate",
    download: "Download",
    login: "Login",
    register: "Register",
    email: "Email",
    passwordLabel: "Password",
    name: "Name",
    welcome: "Welcome to CyberGuard AI",
    loginDescription: "Manage your cybersecurity intelligently.",
    noAccount: "Don't have an account?",
    haveAccount: "Already have an account?",
    createAccount: "Create account",
    signIn: "Sign in",
    logout: "Logout",
    darkMode: "Dark mode",
    lightMode: "Light mode",
    systemScanner: "System Scanner",
    scanDescription: "Scan your device for threats.",
    scanning: "Scanning...",
    scanComplete: "Scan completed.",
    scanDescriptionLong:
      "The scanner uses the security engine to analyze available security signals.",
    deviceName: "Device",
    ipAddress: "IP Address",
    status: "Status",
    risk: "Risk",
    type: "Type",
    threatName: "Threat Name",
    severity: "Severity",
    time: "Time",
    action: "Action",
    block: "Block",
    blockedMessage: "Threat blocked.",
    passwordSecurity: "Password Security",
    passwordPlaceholder: "Enter your password",
    weak: "Weak",
    fair: "Fair",
    strong: "Strong",
    excellent: "Excellent",
    passwordTips: "Password Tips",
    passwordTip1: "Use at least 12 characters.",
    passwordTip2: "Mix uppercase and lowercase letters.",
    passwordTip3: "Add numbers and special characters.",
    passwordTip4: "Do not use personal information.",
    networkMonitor: "Network Monitor",
    secure: "Secure",
    reportsTitle: "Security Reports",
    reportDescription: "Generate a system security report.",
    generateReport: "Generate Report",
    aiTitle: "AI Security Assistant",
    aiPlaceholder: "Ask a question...",
    aiWelcome:
      "Hello! I am CyberGuard AI. I can analyze your security state and answer cybersecurity questions.",
    logsTitle: "Security Logs",
    notificationsTitle: "Notifications",
    newsTitle: "Cyber News",
    profileTitle: "Profile",
    settingsTitle: "Settings",
    helpTitle: "Help Center",
    language: "Language",
    theme: "Theme",
    accountSecurity: "Account Security",
    twoFactor: "Two-factor authentication",
    enabled: "Enabled",
    disabled: "Disabled",
    helpText: "Use the sections below if you need help with CyberGuard AI.",
    serverError: "Server connection error.",
    invalidLogin: "Invalid email or password.",
    registered: "Registration successful.",
    loggedIn: "Login successful.",
    reportGenerated: "Report data successfully loaded.",
  },
} as const;

const menuGroups = [
  {
    key: "main",
    items: [
      ["dashboard", "Dashboard", "▦"],
      ["security", "Security", "◈"],
    ],
  },
  {
    key: "securityGroup",
    items: [
      ["scan", "System Scanner", "⌕"],
      ["devices", "Devices", "▣"],
      ["threats", "Threats", "⚠"],
      ["password", "Password Security", "◆"],
      ["network", "Network Monitor", "⌁"],
    ],
  },
  {
    key: "analytics",
    items: [
      ["reports", "Security Reports", "▤"],
      ["ai", "AI Security", "✦"],
      ["logs", "Security Logs", "☷"],
      ["notifications", "Notifications", "●"],
      ["news", "Cyber News", "◉"],
    ],
  },
  {
    key: "account",
    items: [
      ["profile", "Profile", "♙"],
      ["settings", "Settings", "⚙"],
      ["help", "Help", "?"],
    ],
  },
] as const;

const defaultPasswordPolicy: PasswordPolicy = {
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumber: true,
  requireSpecial: true,
};

function getStoredUser(): User | null {
  try {
    const value = localStorage.getItem("cyberguard_user");

    if (!value) return null;

    const parsed = JSON.parse(value);

    if (
      parsed &&
      typeof parsed.name === "string" &&
      typeof parsed.email === "string"
    ) {
      return parsed;
    }

    return null;
  } catch {
    localStorage.removeItem("cyberguard_user");
    return null;
  }
}

function getStoredLanguage(): Language {
  const value = localStorage.getItem("cyberguard_language");

  if (value === "UZ" || value === "RU" || value === "EN") {
    return value;
  }

  return "UZ";
}

function getStoredTheme(): boolean {
  return localStorage.getItem("cyberguard_theme") !== "light";
}

function formatTime(value?: string): string {
  if (!value) return "—";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString();
}

function mapThreats(
  value: NonNullable<DashboardResponse["threats"]>,
): Threat[] {
  return value.map((item) => ({
    id: item.id,
    name: item.name,
    type: item.type,
    device: item.device_name || "Unknown device",
    severity: item.severity,
    status: item.status,
    time: formatTime(item.detected_at),
    score: item.score,
    description: item.description,
    evidence: item.evidence,
  }));
}

function mapDevices(
  value: NonNullable<DashboardResponse["devices"]>,
): Device[] {
  return value.map((item) => ({
    id: item.id,
    name: item.name,
    type: item.type,
    ip: item.ip || "",
    status: item.status,
    risk: item.risk,
    last_seen: item.last_seen,
    created_at: item.created_at,
  }));
}

function App() {
  const savedToken = localStorage.getItem("cyberguard_token");

  const [language, setLanguage] = useState<Language>(
    getStoredLanguage(),
  );

  const [currentPage, setCurrentPage] =
    useState<Page>("dashboard");

  const [user, setUser] = useState<User | null>(
    getStoredUser(),
  );

  const [isLoggedIn, setIsLoggedIn] =
    useState(Boolean(savedToken));

  const [authChecking, setAuthChecking] =
    useState(Boolean(savedToken));

  const [loginMode, setLoginMode] =
    useState<"login" | "register">("login");

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");

  const [showAuthPassword, setShowAuthPassword] =
    useState(false);

  const [loading, setLoading] = useState(false);
  const [authError, setAuthError] = useState("");
  const [authSuccess, setAuthSuccess] = useState("");

  const [passwordPolicy, setPasswordPolicy] =
    useState<PasswordPolicy>(defaultPasswordPolicy);

  const [darkMode, setDarkMode] =
    useState(getStoredTheme());

  const [securityScore, setSecurityScore] =
    useState(100);

  const [isScanning, setIsScanning] =
    useState(false);

  const [devices, setDevices] =
    useState<Device[]>([]);

  const [threats, setThreats] =
    useState<Threat[]>([]);

  const [notifications, setNotifications] =
    useState<Notification[]>([]);

  const [logs, setLogs] =
    useState<LogItem[]>([]);

  const [search, setSearch] = useState("");
  const [passwordValue, setPasswordValue] =
    useState("");

  const [showPasswordChecker, setShowPasswordChecker] =
    useState(false);

  const [aiQuestion, setAiQuestion] = useState("");
  const [aiAnswer, setAiAnswer] = useState("");
  const [aiLoading, setAiLoading] = useState(false);

  const [showNotifications, setShowNotifications] =
    useState(false);

  const [currentTime, setCurrentTime] =
    useState(new Date());

  const [dataLoading, setDataLoading] =
    useState(false);

  const [dataError, setDataError] = useState("");

  const [reportLoading, setReportLoading] =
    useState(false);

  const [reportMessage, setReportMessage] =
    useState("");

  const t = translations[language];

  useEffect(() => {
    localStorage.setItem(
      "cyberguard_language",
      language,
    );
  }, [language]);

  useEffect(() => {
    localStorage.setItem(
      "cyberguard_theme",
      darkMode ? "dark" : "light",
    );
  }, [darkMode]);

  useEffect(() => {
    const timer = window.setInterval(() => {
      setCurrentTime(new Date());
    }, 1000);

    return () => window.clearInterval(timer);
  }, []);

  async function loadPasswordPolicy() {
    try {
      const data = await apiGet<{
        success: boolean;
        policy?: PasswordPolicy;
      }>("/api/password-policy");

      if (data.policy) {
        setPasswordPolicy({
          ...defaultPasswordPolicy,
          ...data.policy,
        });
      }
    } catch {
      setPasswordPolicy(defaultPasswordPolicy);
    }
  }

  async function loadDashboardData() {
    const token = localStorage.getItem(
      "cyberguard_token",
    );

    if (!token) return;

    setDataLoading(true);
    setDataError("");

    try {
      const [dashboard, notificationData, logData] =
        await Promise.all([
          apiGet<DashboardResponse>("/api/dashboard"),

          apiGet<{
            success: boolean;
            notifications?: Notification[];
          }>("/api/notifications"),

          apiGet<{
            success: boolean;
            logs?: Array<{
              id: number;
              action: string;
              description: string;
              type: string;
              created_at: string;
            }>;
          }>("/api/logs"),
        ]);

      if (typeof dashboard.securityScore === "number") {
        setSecurityScore(dashboard.securityScore);
      }

      if (dashboard.devices) {
        setDevices(mapDevices(dashboard.devices));
      }

      if (dashboard.threats) {
        setThreats(mapThreats(dashboard.threats));
      }

      if (Array.isArray(notificationData.notifications)) {
        setNotifications(
          notificationData.notifications.map((item) => ({
            ...item,
            time: formatTime(item.time),
          })),
        );
      }

      if (Array.isArray(logData.logs)) {
        setLogs(
          logData.logs.map((item) => ({
            id: item.id,
            action: item.action,
            description: item.description,
            time: formatTime(item.created_at),
            type:
              item.type === "danger" ||
              item.type === "warning" ||
              item.type === "success"
                ? item.type
                : "info",
          })),
        );
      }
    } catch (error) {
      setDataError(
        error instanceof Error
          ? error.message
          : t.serverError,
      );
    } finally {
      setDataLoading(false);
    }
  }

  useEffect(() => {
    void loadPasswordPolicy();
  }, []);

  useEffect(() => {
    async function verifyInitialSession() {
      const token = localStorage.getItem(
        "cyberguard_token",
      );

      if (!token) {
        setAuthChecking(false);
        setIsLoggedIn(false);
        return;
      }

      try {
        const data = await apiGet<{
          success: boolean;
          user?: User;
        }>("/api/auth/me");

        if (!data.success || !data.user) {
          throw new Error("Session invalid");
        }

        localStorage.setItem(
          "cyberguard_user",
          JSON.stringify(data.user),
        );

        setUser(data.user);
        setIsLoggedIn(true);

        await loadDashboardData();
      } catch {
        clearSession();
        setUser(null);
        setIsLoggedIn(false);
      } finally {
        setAuthChecking(false);
      }
    }

    void verifyInitialSession();
  }, []);

  const unreadCount = notifications.filter(
    (item) => item.unread,
  ).length;

  const filteredDevices = useMemo(() => {
    const value = search.toLowerCase().trim();

    if (!value) return devices;

    return devices.filter(
      (device) =>
        device.name.toLowerCase().includes(value) ||
        device.type.toLowerCase().includes(value) ||
        device.ip.toLowerCase().includes(value),
    );
  }, [devices, search]);

  const filteredThreats = useMemo(() => {
    const value = search.toLowerCase().trim();

    if (!value) return threats;

    return threats.filter(
      (threat) =>
        threat.name.toLowerCase().includes(value) ||
        threat.type.toLowerCase().includes(value) ||
        threat.device.toLowerCase().includes(value),
    );
  }, [threats, search]);

  const securityStatus =
    securityScore >= 90
      ? "Excellent"
      : securityScore >= 75
        ? "Good"
        : securityScore >= 50
          ? "Warning"
          : "Critical";

  function validateRegistration() {
    const cleanName = name.trim();
    const cleanEmail = email.trim().toLowerCase();

    if (cleanName.length < 2) {
      return "Ism kamida 2 ta belgidan iborat bo‘lishi kerak.";
    }

    if (!cleanEmail) {
      return "Email kiriting.";
    }

    if (!password) {
      return "Parol kiriting.";
    }

    if (password.length < passwordPolicy.minLength) {
      return `Parol kamida ${passwordPolicy.minLength} ta belgidan iborat bo‘lishi kerak.`;
    }

    if (
      passwordPolicy.requireUppercase &&
      !/[A-Z]/.test(password)
    ) {
      return "Parolda kamida 1 ta katta harf bo‘lishi kerak.";
    }

    if (
      passwordPolicy.requireLowercase &&
      !/[a-z]/.test(password)
    ) {
      return "Parolda kamida 1 ta kichik harf bo‘lishi kerak.";
    }

    if (
      passwordPolicy.requireNumber &&
      !/[0-9]/.test(password)
    ) {
      return "Parolda kamida 1 ta raqam bo‘lishi kerak.";
    }

    if (
      passwordPolicy.requireSpecial &&
      !/[^A-Za-z0-9]/.test(password)
    ) {
      return "Parolda kamida 1 ta maxsus belgi bo‘lishi kerak.";
    }

    return "";
  }

  function getPasswordStrength(value: string) {
    if (!value) {
      return {
        score: 0,
        label: "",
      };
    }

    let score = 0;

    if (value.length >= 8) score++;
    if (value.length >= 12) score++;
    if (/[A-Z]/.test(value)) score++;
    if (/[a-z]/.test(value)) score++;
    if (/[0-9]/.test(value)) score++;
    if (/[^A-Za-z0-9]/.test(value)) score++;

    if (score <= 2) {
      return {
        score,
        label: t.weak,
      };
    }

    if (score <= 4) {
      return {
        score,
        label: t.fair,
      };
    }

    if (score === 5) {
      return {
        score,
        label: t.strong,
      };
    }

    return {
      score,
      label: t.excellent,
    };
  }

  async function handleLogin(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();

    setLoading(true);
    setAuthError("");
    setAuthSuccess("");

    const cleanEmail = email.trim().toLowerCase();

    try {
      const data = await apiPost<{
        success: boolean;
        token?: string;
        user?: User;
        message?: string;
      }>("/api/login", {
        email: cleanEmail,
        password,
      });

      if (
        !data.success ||
        !data.token ||
        !data.user
      ) {
        throw new Error(
          data.message || t.invalidLogin,
        );
      }

      localStorage.setItem(
        "cyberguard_token",
        data.token,
      );

      localStorage.setItem(
        "cyberguard_user",
        JSON.stringify(data.user),
      );

      setUser(data.user);
      setIsLoggedIn(true);
      setCurrentPage("dashboard");

      setEmail("");
      setPassword("");
      setAuthSuccess(t.loggedIn);

      await loadDashboardData();
    } catch (error) {
      setAuthError(
        error instanceof Error
          ? error.message
          : t.serverError,
      );
    } finally {
      setLoading(false);
    }
  }

  async function handleRegister(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();

    setLoading(true);
    setAuthError("");
    setAuthSuccess("");

    const validationError =
      validateRegistration();

    if (validationError) {
      setAuthError(validationError);
      setLoading(false);
      return;
    }

    const cleanName = name.trim();
    const cleanEmail = email.trim().toLowerCase();

    try {
      const data = await apiPost<{
        success: boolean;
        token?: string;
        user?: User;
        message?: string;
      }>("/api/register", {
        name: cleanName,
        email: cleanEmail,
        password,
      });

      if (!data.success) {
        throw new Error(
          data.message || t.serverError,
        );
      }

      /*
       * Agar backend register token qaytarsa,
       * foydalanuvchini darhol dashboardga kiritamiz.
       */
      if (data.token && data.user) {
        localStorage.setItem(
          "cyberguard_token",
          data.token,
        );

        localStorage.setItem(
          "cyberguard_user",
          JSON.stringify(data.user),
        );

        setUser(data.user);
        setIsLoggedIn(true);
        setCurrentPage("dashboard");

        setName("");
        setEmail("");
        setPassword("");
        setAuthSuccess(t.registered);

        await loadDashboardData();
        return;
      }

      /*
       * Hozirgi backend faqat success/message
       * qaytarsa, avtomatik login qilamiz.
       */
      const loginData = await apiPost<{
        success: boolean;
        token?: string;
        user?: User;
        message?: string;
      }>("/api/login", {
        email: cleanEmail,
        password,
      });

      if (
        !loginData.success ||
        !loginData.token ||
        !loginData.user
      ) {
        setLoginMode("login");
        setName("");
        setPassword("");
        setAuthSuccess(t.registered);
        return;
      }

      localStorage.setItem(
        "cyberguard_token",
        loginData.token,
      );

      localStorage.setItem(
        "cyberguard_user",
        JSON.stringify(loginData.user),
      );

      setUser(loginData.user);
      setIsLoggedIn(true);
      setCurrentPage("dashboard");

      setName("");
      setEmail("");
      setPassword("");
      setAuthSuccess(t.registered);

      await loadDashboardData();
    } catch (error) {
      setAuthError(
        error instanceof Error
          ? error.message
          : t.serverError,
      );
    } finally {
      setLoading(false);
    }
  }

  async function logout() {
    try {
      if (localStorage.getItem("cyberguard_token")) {
        await apiPost("/api/logout");
      }
    } catch {
      // Local cleanup always happens.
    } finally {
      clearSession();

      setUser(null);
      setIsLoggedIn(false);
      setCurrentPage("dashboard");
      setShowNotifications(false);
      setSearch("");
      setAiAnswer("");
      setAiQuestion("");
      setDevices([]);
      setThreats([]);
      setNotifications([]);
      setLogs([]);
    }
  }

  function addLocalLog(
    action: string,
    description: string,
    type:
      | "success"
      | "warning"
      | "danger"
      | "info" = "info",
  ) {
    setLogs((previous) => [
      {
        id: Date.now(),
        action,
        description,
        time: new Date().toLocaleTimeString(),
        type,
      },
      ...previous,
    ]);
  }

  function addLocalNotification(
    title: string,
    message: string,
    type:
      | "success"
      | "warning"
      | "danger"
      | "info",
  ) {
    setNotifications((previous) => [
      {
        id: Date.now(),
        title,
        message,
        time: "Just now",
        unread: true,
        type,
      },
      ...previous,
    ]);
  }

  async function handleScan() {
    if (isScanning) return;

    setIsScanning(true);
    setDataError("");

    try {
      const defaultDevice = devices[0];

      const data = await apiPost<{
        success: boolean;
        score?: number;
        threats?: Threat[];
        message?: string;
        scanId?: number;
      }>("/api/security/scan", {
        deviceId: defaultDevice?.id,
      });

      if (!data.success) {
        throw new Error(
          data.message || "Security scan failed.",
        );
      }

      if (typeof data.score === "number") {
        setSecurityScore(data.score);
      }

      if (Array.isArray(data.threats)) {
        setThreats(
          data.threats.map((item) => ({
            ...item,
            device:
              item.device || "Unknown device",
            time: item.time || "Just now",
          })),
        );
      }

      await loadDashboardData();

      addLocalNotification(
        "System scan",
        t.scanComplete,
        "success",
      );

      addLocalLog(
        "System scan",
        `Security scan completed${
          data.scanId
            ? ` (#${data.scanId})`
            : ""
        }.`,
        "success",
      );
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : t.serverError;

      setDataError(message);

      addLocalNotification(
        "Scan error",
        message,
        "danger",
      );

      addLocalLog(
        "System scan failed",
        message,
        "danger",
      );
    } finally {
      setIsScanning(false);
    }
  }

  async function blockThreat(id: number) {
    try {
      const data = await apiPost<{
        success: boolean;
        threat?: {
          id: number;
          status: string;
        };
        securityScore?: number;
        message?: string;
      }>(`/api/threats/${id}/block`);

      if (!data.success) {
        throw new Error(
          data.message ||
            "Threatni bloklab bo‘lmadi.",
        );
      }

      setThreats((previous) =>
        previous.map((threat) =>
          threat.id === id
            ? {
                ...threat,
                status: "Blocked",
              }
            : threat,
        ),
      );

      if (
        typeof data.securityScore === "number"
      ) {
        setSecurityScore(data.securityScore);
      }

      addLocalNotification(
        "Threat blocked",
        t.blockedMessage,
        "success",
      );

      addLocalLog(
        "Threat blocked",
        `Threat #${id} was blocked.`,
        "success",
      );

      await loadDashboardData();
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "Threatni bloklashda xatolik.";

      addLocalNotification(
        "Block failed",
        message,
        "danger",
      );
    }
  }

  async function toggleDevice(id: number) {
    try {
      const data = await apiPatch<{
        success: boolean;
        device?: Device;
        message?: string;
      }>(`/api/devices/${id}/status`);

      if (!data.success || !data.device) {
        throw new Error(
          data.message ||
            "Device statusini o‘zgartirib bo‘lmadi.",
        );
      }

      setDevices((previous) =>
        previous.map((device) =>
          device.id === id
            ? {
                ...device,
                ...data.device,
              }
            : device,
        ),
      );

      addLocalLog(
        "Device status changed",
        `${data.device.name}: ${data.device.status}`,
        "info",
      );
    } catch (error) {
      addLocalNotification(
        "Device error",
        error instanceof Error
          ? error.message
          : "Device update failed.",
        "danger",
      );
    }
  }

  async function handleAIAnalyze() {
    if (!aiQuestion.trim() || aiLoading) {
      return;
    }

    setAiLoading(true);

    try {
      const data =
        await apiPost<AIResponse>(
          "/api/ai/analyze",
          {
            question: aiQuestion.trim(),
          },
        );

      if (!data.success || !data.answer) {
        throw new Error(
          data.message ||
            "AI javob qaytara olmadi.",
        );
      }

      setAiAnswer(data.answer);

      if (
        typeof data.securityScore ===
        "number"
      ) {
        setSecurityScore(
          data.securityScore,
        );
      }

      addLocalLog(
        "AI analysis",
        `AI analyzed: ${aiQuestion}`,
        "info",
      );
    } catch (error) {
      setAiAnswer(
        error instanceof Error
          ? error.message
          : t.serverError,
      );
    } finally {
      setAiLoading(false);
    }
  }

  async function generateReport() {
    if (reportLoading) return;

    setReportLoading(true);
    setReportMessage("");

    try {
      const data =
        await apiGet<{
          success: boolean;
          report?: {
            generatedAt: string;
            securityScore: number;
            totalThreats: number;
            activeThreats: number;
            blockedThreats: number;
            deviceCount: number;
            incidentCount: number;
            recommendations: string[];
          };
          message?: string;
        }>("/api/reports/security");

      if (!data.success || !data.report) {
        throw new Error(
          data.message ||
            "Report data unavailable.",
        );
      }

      const report = data.report;

      const text = [
        "CYBERGUARD AI",
        "SECURITY HEALTH REPORT",
        "",
        `Generated: ${formatTime(
          report.generatedAt,
        )}`,
        "",
        `Security Score: ${report.securityScore}%`,
        `Total Threats: ${report.totalThreats}`,
        `Active Threats: ${report.activeThreats}`,
        `Blocked Threats: ${report.blockedThreats}`,
        `Devices: ${report.deviceCount}`,
        `Incidents: ${report.incidentCount}`,
        "",
        "Recommendations:",
        ...report.recommendations.map(
          (item, index) =>
            `${index + 1}. ${item}`,
        ),
      ].join("\n");

      const blob = new Blob([text], {
        type: "text/plain;charset=utf-8",
      });

      const url =
        URL.createObjectURL(blob);

      const anchor =
        document.createElement("a");

      anchor.href = url;

      anchor.download =
        `cyberguard-security-report-${new Date()
          .toISOString()
          .slice(0, 10)}.txt`;

      document.body.appendChild(anchor);

      anchor.click();
      anchor.remove();

      URL.revokeObjectURL(url);

      setReportMessage(
        t.reportGenerated,
      );

      addLocalLog(
        "Report generated",
        "Security report downloaded.",
        "success",
      );
    } catch (error) {
      setReportMessage(
        error instanceof Error
          ? error.message
          : t.serverError,
      );
    } finally {
      setReportLoading(false);
    }
  }

  async function markNotificationsRead() {
    try {
      await apiPost(
        "/api/notifications/read-all",
      );
    } catch {
      // UI still updates.
    }

    setNotifications((previous) =>
      previous.map((item) => ({
        ...item,
        unread: false,
      })),
    );
  }

  function navigate(page: Page) {
    setCurrentPage(page);
    setSearch("");
    setShowNotifications(false);

    if (
      page === "dashboard" ||
      page === "notifications"
    ) {
      void loadDashboardData();
    }
  }

  function refreshData() {
    void loadDashboardData();
  }

  function renderDashboard() {
    const activeThreatCount =
      threats.filter(
        (item) => item.status === "Active",
      ).length;

    const onlineDeviceCount =
      devices.filter(
        (item) => item.status === "Online",
      ).length;

    return (
      <>
        <div className="page-heading">
          <div>
            <h1>{t.dashboard}</h1>
            <p>
              {dataLoading
                ? "Security data loading..."
                : t.overview}
            </p>
          </div>

          <button
            className="primary-button"
            onClick={() =>
              void handleScan()
            }
            disabled={isScanning}
          >
            {isScanning
              ? t.scanning
              : t.startScan}
          </button>
        </div>

        {dataError && (
          <div className="auth-error">
            <span>!</span>
            {dataError}
          </div>
        )}

        <section className="stats-grid">
          <div className="stat-card">
            <div className="stat-icon green">
              ✓
            </div>

            <div>
              <span>{t.securityScore}</span>
              <strong>{securityScore}%</strong>
              <small>{securityStatus}</small>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon red">!</div>

            <div>
              <span>{t.threatsFound}</span>
              <strong>{activeThreatCount}</strong>
              <small>{t.active}</small>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon blue">▣</div>

            <div>
              <span>{t.devicesCount}</span>
              <strong>{devices.length}</strong>
              <small>
                {onlineDeviceCount} {t.online}
              </small>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon purple">⌁</div>

            <div>
              <span>{t.networkStatus}</span>
              <strong>{securityScore}%</strong>
              <small>
                {securityScore >= 80
                  ? t.secure
                  : "Needs attention"}
              </small>
            </div>
          </div>
        </section>

        <section className="dashboard-columns">
          <div className="panel large-panel">
            <div className="panel-header">
              <div>
                <h2>{t.securityScore}</h2>
                <p>{t.protected}</p>
              </div>

              <div
                className="score-circle"
                style={
                  {
                    "--score": securityScore,
                  } as CSSProperties
                }
              >
                <span>{securityScore}</span>
                <small>%</small>
              </div>
            </div>

            <div className="big-progress">
              <div
                style={{
                  width: `${securityScore}%`,
                }}
              />
            </div>

            <div className="score-details">
              <div>
                <span>Firewall</span>
                <strong>
                  {securityScore >= 80
                    ? "Active"
                    : "Review"}
                </strong>
              </div>

              <div>
                <span>Antivirus</span>
                <strong>
                  {securityScore >= 80
                    ? "Protected"
                    : "Review"}
                </strong>
              </div>

              <div>
                <span>Network</span>
                <strong>
                  {securityScore >= 80
                    ? "Secure"
                    : "Review"}
                </strong>
              </div>

              <div>
                <span>Passwords</span>
                <strong>Review</strong>
              </div>
            </div>
          </div>

          <div className="panel">
            <div className="panel-title">
              <h2>{t.quickActions}</h2>
            </div>

            <div className="quick-actions">
              <button
                onClick={() =>
                  navigate("scan")
                }
              >
                <span>⌕</span>
                {t.scanNow}
              </button>

              <button
                onClick={() =>
                  navigate("devices")
                }
              >
                <span>▣</span>
                {t.devices}
              </button>

              <button
                onClick={() =>
                  navigate("password")
                }
              >
                <span>◆</span>
                {t.passwordSecurity}
              </button>

              <button
                onClick={() =>
                  navigate("ai")
                }
              >
                <span>✦</span>
                {t.ai}
              </button>
            </div>
          </div>
        </section>

        <section className="dashboard-columns">
          <div className="panel">
            <div className="panel-header">
              <div>
                <h2>{t.threats}</h2>
                <p>{t.recentActivity}</p>
              </div>

              <button
                className="text-button"
                onClick={() =>
                  navigate("threats")
                }
              >
                {t.viewAll}
              </button>
            </div>

            <div className="mini-list">
              {threats.slice(0, 4).map(
                (threat) => (
                  <div
                    className="mini-row"
                    key={threat.id}
                  >
                    <div className="mini-icon danger">
                      !
                    </div>

                    <div className="mini-content">
                      <strong>
                        {threat.name}
                      </strong>

                      <span>
                        {threat.device}
                      </span>
                    </div>

                    <StatusBadge
                      value={
                        threat.status
                      }
                    />
                  </div>
                ),
              )}

              {threats.length === 0 && (
                <div className="mini-row">
                  <div className="mini-icon success">
                    ✓
                  </div>

                  <div className="mini-content">
                    <strong>
                      No threats recorded
                    </strong>

                    <span>
                      Run a security scan to check your device.
                    </span>
                  </div>
                </div>
              )}
            </div>
          </div>

          <div className="panel">
            <div className="panel-header">
              <div>
                <h2>{t.activity}</h2>
                <p>{t.recentActivity}</p>
              </div>

              <button
                className="text-button"
                onClick={() =>
                  navigate("logs")
                }
              >
                {t.viewAll}
              </button>
            </div>

            <div className="mini-list">
              {logs.slice(0, 4).map(
                (log) => (
                  <div
                    className="mini-row"
                    key={log.id}
                  >
                    <div
                      className={`mini-icon ${log.type}`}
                    >
                      ✓
                    </div>

                    <div className="mini-content">
                      <strong>
                        {log.action}
                      </strong>

                      <span>
                        {log.description}
                      </span>
                    </div>

                    <time>{log.time}</time>
                  </div>
                ),
              )}

              {logs.length === 0 && (
                <div className="mini-row">
                  <div className="mini-icon info">
                    i
                  </div>

                  <div className="mini-content">
                    <strong>
                      No activity
                    </strong>

                    <span>
                      Security events will appear here.
                    </span>
                  </div>
                </div>
              )}
            </div>
          </div>
        </section>
      </>
    );
  }

  function renderSecurity() {
    return (
      <>
        <PageHeader
          title={t.security}
          description="CyberGuard AI security overview"
          action={
            <button
              className="secondary-button"
              onClick={refreshData}
            >
              ↻ {t.refresh}
            </button>
          }
        />

        <div className="security-banner">
          <div className="security-banner-icon">
            {securityScore >= 80 ? "✓" : "!"}
          </div>

          <div>
            <h2>
              {securityScore >= 80
                ? "System is protected"
                : "Security needs attention"}
            </h2>

            <p>
              CyberGuard security engine is monitoring
              the current account state.
            </p>
          </div>

          <strong>{securityScore}%</strong>
        </div>

        <section className="security-grid">
          <SecurityCard
            icon="◉"
            title="Firewall"
            value={
              securityScore >= 70
                ? "Active"
                : "Review"
            }
            progress={Math.min(
              100,
              securityScore + 5,
            )}
          />

          <SecurityCard
            icon="◆"
            title="Antivirus"
            value={
              securityScore >= 70
                ? "Protected"
                : "Review"
            }
            progress={securityScore}
          />

          <SecurityCard
            icon="⌁"
            title="Network"
            value={
              securityScore >= 70
                ? "Secure"
                : "Review"
            }
            progress={Math.max(
              0,
              securityScore - 2,
            )}
          />

          <SecurityCard
            icon="●"
            title="Privacy"
            value={
              securityScore >= 75
                ? "Protected"
                : "Review"
            }
            progress={Math.max(
              0,
              securityScore - 5,
            )}
          />

          <SecurityCard
            icon="🔑"
            title="Passwords"
            value="Needs attention"
            progress={78}
          />

          <SecurityCard
            icon="◈"
            title="Updates"
            value={
              securityScore >= 75
                ? "Up to date"
                : "Review"
            }
            progress={Math.max(
              0,
              securityScore - 1,
            )}
          />
        </section>
      </>
    );
  }

  function renderScan() {
    return (
      <>
        <PageHeader
          title={t.systemScanner}
          description={t.scanDescription}
        />

        <div className="scanner-layout">
          <div className="panel scanner-card">
            <div className="scanner-ring">
              <span>
                {isScanning
                  ? "..."
                  : `${securityScore}%`}
              </span>
            </div>

            <h2>
              {isScanning
                ? t.scanning
                : "Ready to scan"}
            </h2>

            <p>{t.scanDescriptionLong}</p>

            <button
              className="primary-button large-button"
              onClick={() =>
                void handleScan()
              }
              disabled={isScanning}
            >
              {isScanning
                ? t.scanning
                : t.startScan}
            </button>
          </div>

          <div className="panel">
            <div className="panel-title">
              <h2>Scan checks</h2>
            </div>

            <div className="check-list">
              <CheckItem text="Malware detection" />
              <CheckItem text="System vulnerabilities" />
              <CheckItem text="Suspicious processes" />
              <CheckItem text="Network connections" />
              <CheckItem text="Password security" />
              <CheckItem text="System updates" />
            </div>
          </div>
        </div>
      </>
    );
  }

  function renderDevices() {
    return (
      <>
        <PageHeader
          title={t.devices}
          description="Monitor connected devices"
          action={
            <button
              className="secondary-button"
              onClick={refreshData}
            >
              ↻ {t.refresh}
            </button>
          }
        />

        <div className="toolbar">
          <div className="search-box">
            <span>⌕</span>

            <input
              value={search}
              onChange={(event) =>
                setSearch(
                  event.target.value,
                )
              }
              placeholder={t.search}
            />
          </div>

          <div className="toolbar-stat">
            {devices.length} devices
          </div>
        </div>

        <div className="panel table-panel">
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>{t.deviceName}</th>
                  <th>{t.type}</th>
                  <th>{t.ipAddress}</th>
                  <th>{t.status}</th>
                  <th>{t.risk}</th>
                  <th>{t.action}</th>
                </tr>
              </thead>

              <tbody>
                {filteredDevices.map(
                  (device) => (
                    <tr key={device.id}>
                      <td>
                        <div className="table-device">
                          <div className="device-avatar">
                            {device.type
                              .toLowerCase()
                              .includes("mobile")
                              ? "●"
                              : "▣"}
                          </div>

                          <strong>
                            {device.name}
                          </strong>
                        </div>
                      </td>

                      <td>{device.type}</td>

                      <td>
                        <code>
                          {device.ip || "—"}
                        </code>
                      </td>

                      <td>
                        <StatusBadge
                          value={
                            device.status
                          }
                        />
                      </td>

                      <td>
                        <RiskBadge
                          value={
                            device.risk
                          }
                        />
                      </td>

                      <td>
                        <button
                          className="small-button"
                          onClick={() =>
                            void toggleDevice(
                              device.id,
                            )
                          }
                        >
                          {device.status ===
                          "Online"
                            ? t.offline
                            : t.online}
                        </button>
                      </td>
                    </tr>
                  ),
                )}
              </tbody>
            </table>
          </div>

          {devices.length === 0 && (
            <div className="mini-row">
              <div className="mini-icon info">
                i
              </div>

              <div className="mini-content">
                <strong>No devices</strong>

                <span>
                  Your protected device will appear here
                  after account setup.
                </span>
              </div>
            </div>
          )}
        </div>
      </>
    );
  }

  function renderThreats() {
    const active = threats.filter(
      (item) => item.status === "Active",
    ).length;

    const blocked = threats.filter(
      (item) => item.status === "Blocked",
    ).length;

    return (
      <>
        <PageHeader
          title={t.threats}
          description="Detected security threats"
          action={
            <button
              className="secondary-button"
              onClick={refreshData}
            >
              ↻ {t.refresh}
            </button>
          }
        />

        <div className="toolbar">
          <div className="search-box">
            <span>⌕</span>

            <input
              value={search}
              onChange={(event) =>
                setSearch(
                  event.target.value,
                )
              }
              placeholder={t.search}
            />
          </div>

          <div className="threat-summary">
            <span className="summary-danger">
              {active} active
            </span>

            <span className="summary-safe">
              {blocked} blocked
            </span>
          </div>
        </div>

        <div className="threat-grid">
          {filteredThreats.map(
            (threat) => (
              <div
                className="threat-card"
                key={threat.id}
              >
                <div className="threat-card-top">
                  <div className="threat-icon">
                    !
                  </div>

                  <SeverityBadge
                    value={
                      threat.severity
                    }
                  />
                </div>

                <h3>{threat.name}</h3>

                <div className="threat-info">
                  <span>
                    <b>Type:</b>{" "}
                    {threat.type}
                  </span>

                  <span>
                    <b>Device:</b>{" "}
                    {threat.device}
                  </span>

                  <span>
                    <b>Time:</b>{" "}
                    {threat.time}
                  </span>

                  {typeof threat.score ===
                    "number" && (
                    <span>
                      <b>Risk score:</b>{" "}
                      {threat.score}%
                    </span>
                  )}

                  {threat.description && (
                    <span>
                      <b>Analysis:</b>{" "}
                      {threat.description}
                    </span>
                  )}
                </div>

                <div className="threat-card-bottom">
                  <StatusBadge
                    value={threat.status}
                  />

                  {threat.status ===
                    "Active" && (
                    <button
                      className="danger-button"
                      onClick={() =>
                        void blockThreat(
                          threat.id,
                        )
                      }
                    >
                      {t.block}
                    </button>
                  )}
                </div>
              </div>
            ),
          )}
        </div>

        {filteredThreats.length === 0 && (
          <div className="panel">
            <div className="panel-title">
              <h2>No threats found</h2>
            </div>

            <div className="tips-list">
              <Tip text="Run a security scan to create the latest security assessment." />
            </div>
          </div>
        )}
      </>
    );
  }

  function renderPassword() {
    const strength =
      getPasswordStrength(passwordValue);

    const percentage = Math.min(
      100,
      (strength.score / 6) * 100,
    );

    return (
      <>
        <PageHeader
          title={t.passwordSecurity}
          description="Check your password strength locally"
        />

        <div className="password-layout">
          <div className="panel password-card">
            <div className="password-lock">
              🔐
            </div>

            <h2>{t.passwordSecurity}</h2>

            <p>
              Test your password without sending it
              to the server.
            </p>

            <div className="password-input">
              <input
                type={
                  showPasswordChecker
                    ? "text"
                    : "password"
                }
                value={passwordValue}
                onChange={(event) =>
                  setPasswordValue(
                    event.target.value,
                  )
                }
                placeholder={
                  t.passwordPlaceholder
                }
              />

              <button
                type="button"
                onClick={() =>
                  setShowPasswordChecker(
                    (value) => !value,
                  )
                }
              >
                {showPasswordChecker
                  ? "🙈"
                  : "👁"}
              </button>
            </div>

            {passwordValue && (
              <>
                <div className="password-strength">
                  <div>
                    <span>
                      {strength.label}
                    </span>

                    <strong>
                      {Math.round(
                        percentage,
                      )}
                      %
                    </strong>
                  </div>

                  <div className="strength-bar">
                    <div
                      style={{
                        width: `${percentage}%`,
                      }}
                    />
                  </div>
                </div>

                <div className="password-rules">
                  <Rule
                    ok={
                      passwordValue.length >=
                      passwordPolicy.minLength
                    }
                    text={`${passwordPolicy.minLength}+ characters`}
                  />

                  <Rule
                    ok={/[A-Z]/.test(
                      passwordValue,
                    )}
                    text="Uppercase letter"
                  />

                  <Rule
                    ok={/[a-z]/.test(
                      passwordValue,
                    )}
                    text="Lowercase letter"
                  />

                  <Rule
                    ok={/[0-9]/.test(
                      passwordValue,
                    )}
                    text="Number"
                  />

                  <Rule
                    ok={/[^A-Za-z0-9]/.test(
                      passwordValue,
                    )}
                    text="Special character"
                  />
                </div>
              </>
            )}
          </div>

          <div className="panel">
            <div className="panel-title">
              <h2>{t.passwordTips}</h2>
            </div>

            <div className="tips-list">
              <Tip text={t.passwordTip1} />
              <Tip text={t.passwordTip2} />
              <Tip text={t.passwordTip3} />
              <Tip text={t.passwordTip4} />
            </div>
          </div>
        </div>
      </>
    );
  }

  function renderNetwork() {
    const secure = securityScore >= 80;

    return (
      <>
        <PageHeader
          title={t.networkMonitor}
          description="Monitor your network security"
          action={
            <button
              className="secondary-button"
              onClick={refreshData}
            >
              ↻ {t.refresh}
            </button>
          }
        />

        <div className="network-top">
          <div className="network-status-card">
            <div className="network-pulse">
              <span />
            </div>

            <div>
              <span>Connection status</span>

              <h2>
                {secure
                  ? t.secure
                  : "Needs attention"}
              </h2>
            </div>

            <strong>{securityScore}%</strong>
          </div>

          <div className="network-metric">
            <span>Protected devices</span>

            <strong>{devices.length}</strong>

            <small>
              {
                devices.filter(
                  (device) =>
                    device.status ===
                    "Online",
                ).length
              }{" "}
              online
            </small>
          </div>

          <div className="network-metric">
            <span>Active threats</span>

            <strong>
              {
                threats.filter(
                  (threat) =>
                    threat.status ===
                    "Active",
                ).length
              }
            </strong>

            <small>Live security state</small>
          </div>

          <div className="network-metric">
            <span>Security score</span>

            <strong>
              {securityScore}%
            </strong>

            <small>{securityStatus}</small>
          </div>
        </div>

        <div className="network-grid">
          <div className="panel network-chart">
            <div className="panel-title">
              <h2>Network security</h2>
            </div>

            <div className="fake-chart">
              {[
                securityScore * 0.65,
                securityScore * 0.72,
                securityScore * 0.61,
                securityScore * 0.78,
                securityScore * 0.55,
                securityScore * 0.82,
                securityScore * 0.67,
                securityScore * 0.86,
                securityScore * 0.7,
                securityScore * 0.79,
                securityScore * 0.64,
                securityScore * 0.9,
              ].map(
                (height, index) => (
                  <div
                    className="chart-bar"
                    key={index}
                    style={{
                      height: `${Math.max(
                        8,
                        Math.min(
                          95,
                          height,
                        ),
                      )}%`,
                    }}
                  />
                ),
              )}
            </div>
          </div>

          <div className="panel">
            <div className="panel-title">
              <h2>Network details</h2>
            </div>

            <div className="details-list">
              <Detail
                label="Devices"
                value={`${devices.length}`}
              />

              <Detail
                label="Online"
                value={`${devices.filter(
                  (device) =>
                    device.status ===
                    "Online",
                ).length}`}
              />

              <Detail
                label="Active threats"
                value={`${threats.filter(
                  (threat) =>
                    threat.status ===
                    "Active",
                ).length}`}
              />

              <Detail
                label="Risk state"
                value={securityStatus}
              />

              <Detail
                label="Protection"
                value={`${securityScore}%`}
              />
            </div>
          </div>
        </div>
      </>
    );
  }

  function renderReports() {
    const activeThreats =
      threats.filter(
        (threat) =>
          threat.status === "Active",
      ).length;

    return (
      <>
        <PageHeader
          title={t.reportsTitle}
          description={t.reportDescription}
        />

        <div className="report-hero">
          <div className="report-icon">
            ▤
          </div>

          <div>
            <h2>Security Health Report</h2>

            <p>
              Backend-generated security report
              with real account data.
            </p>
          </div>

          <button
            className="primary-button"
            onClick={() =>
              void generateReport()
            }
            disabled={reportLoading}
          >
            {reportLoading
              ? "Generating..."
              : t.generateReport}
          </button>
        </div>

        {reportMessage && (
          <div className="auth-success">
            <span>✓</span>
            {reportMessage}
          </div>
        )}

        <div className="report-grid">
          <ReportCard
            title="Security score"
            value={`${securityScore}%`}
            text="Current protection score"
          />

          <ReportCard
            title="Threats"
            value={`${threats.length}`}
            text={`${activeThreats} active`}
          />

          <ReportCard
            title="Devices"
            value={`${devices.length}`}
            text="Registered devices"
          />

          <ReportCard
            title="Network"
            value={
              securityScore >= 80
                ? "Secure"
                : "Review"
            }
            text="Current status"
          />
        </div>

        <div className="panel">
          <div className="panel-title">
            <h2>
              Security recommendations
            </h2>
          </div>

          <div className="recommendation-list">
            <Tip text="Review active threats regularly." />
            <Tip text="Keep all software updated." />
            <Tip text="Run a full system scan regularly." />
            <Tip text="Check unknown devices on your network." />
            <Tip text="Use MFA on important accounts." />
          </div>
        </div>
      </>
    );
  }

  function renderAI() {
    return (
      <>
        <PageHeader
          title={t.aiTitle}
          description="Ask CyberGuard AI about your security state"
        />

        <div className="ai-layout">
          <div className="panel ai-chat">
            <div className="ai-header">
              <div className="ai-avatar">
                ✦
              </div>

              <div>
                <h2>CyberGuard AI</h2>
                <span>
                  Online • Security Copilot
                </span>
              </div>
            </div>

            <div className="ai-messages">
              <div className="ai-message bot">
                <div className="message-avatar">
                  AI
                </div>

                <div>
                  <p>{t.aiWelcome}</p>
                </div>
              </div>

              {aiAnswer && (
                <div className="ai-message bot">
                  <div className="message-avatar">
                    AI
                  </div>

                  <div>
                    <p>{aiAnswer}</p>
                  </div>
                </div>
              )}
            </div>

            <div className="ai-input">
              <input
                value={aiQuestion}
                onChange={(event) =>
                  setAiQuestion(
                    event.target.value,
                  )
                }
                onKeyDown={(event) => {
                  if (event.key === "Enter") {
                    void handleAIAnalyze();
                  }
                }}
                placeholder={
                  t.aiPlaceholder
                }
              />

              <button
                className="primary-button"
                onClick={() =>
                  void handleAIAnalyze()
                }
                disabled={aiLoading}
              >
                {aiLoading ? "..." : "➤"}
              </button>
            </div>
          </div>

          <div className="panel ai-suggestions">
            <div className="panel-title">
              <h2>Quick questions</h2>
            </div>

            <button
              onClick={() =>
                setAiQuestion(
                  "Nega mening security score'im past?",
                )
              }
            >
              Nega security scoreim past?
            </button>

            <button
              onClick={() =>
                setAiQuestion(
                  "Tizimimdagi faol tahdidlarni tahlil qil",
                )
              }
            >
              Faol tahdidlarni tahlil qil
            </button>

            <button
              onClick={() =>
                setAiQuestion(
                  "Kompyuterimni qanday xavfsizroq qilishim mumkin?",
                )
              }
            >
              Kompyuterimni qanday himoya qilaman?
            </button>

            <button
              onClick={() =>
                setAiQuestion(
                  "Phishing hujumidan qanday himoyalanaman?",
                )
              }
            >
              Phishingdan himoyalanish
            </button>

            <button
              onClick={() =>
                setAiQuestion(
                  "Network xavfsizligini qanday kuchaytiraman?",
                )
              }
            >
              Network xavfsizligi
            </button>
          </div>
        </div>
      </>
    );
  }

  function renderLogs() {
    return (
      <>
        <PageHeader
          title={t.logsTitle}
          description="All security events"
          action={
            <button
              className="secondary-button"
              onClick={refreshData}
            >
              ↻ {t.refresh}
            </button>
          }
        />

        <div className="panel logs-panel">
          {logs.map((log) => (
            <div
              className="log-row"
              key={log.id}
            >
              <div
                className={`log-icon ${log.type}`}
              >
                {log.type === "danger"
                  ? "!"
                  : log.type ===
                      "warning"
                    ? "⚠"
                    : log.type ===
                        "info"
                      ? "i"
                      : "✓"}
              </div>

              <div className="log-content">
                <strong>{log.action}</strong>
                <span>
                  {log.description}
                </span>
              </div>

              <time>{log.time}</time>
            </div>
          ))}

          {logs.length === 0 && (
            <div className="mini-row">
              <div className="mini-icon info">
                i
              </div>

              <div className="mini-content">
                <strong>No logs yet</strong>

                <span>
                  Security actions will appear here.
                </span>
              </div>
            </div>
          )}
        </div>
      </>
    );
  }

  function renderNotifications() {
    return (
      <>
        <PageHeader
          title={t.notificationsTitle}
          description="Security alerts and messages"
          action={
            <button
              className="secondary-button"
              onClick={() =>
                void markNotificationsRead()
              }
            >
              Mark all as read
            </button>
          }
        />

        <div className="notification-page-list">
          {notifications.map(
            (notification) => (
              <div
                className={`notification-card ${
                  notification.unread
                    ? "unread"
                    : ""
                }`}
                key={notification.id}
              >
                <div
                  className={`notification-icon ${notification.type}`}
                >
                  {notification.type ===
                  "danger"
                    ? "!"
                    : notification.type ===
                        "warning"
                      ? "⚠"
                      : notification.type ===
                          "success"
                        ? "✓"
                        : "i"}
                </div>

                <div>
                  <h3>
                    {notification.title}
                  </h3>

                  <p>
                    {notification.message}
                  </p>

                  <time>
                    {notification.time}
                  </time>
                </div>

                {notification.unread && (
                  <span className="unread-dot" />
                )}
              </div>
            ),
          )}

          {notifications.length === 0 && (
            <div className="panel">
              <div className="panel-title">
                <h2>No notifications</h2>
              </div>
            </div>
          )}
        </div>
      </>
    );
  }

  function renderNews() {
    const news = [
      {
        title:
          "CyberGuard security intelligence",
        category:
          "Threat Intelligence",
        date: "Current",
      },
      {
        title:
          "Multi-factor authentication protection",
        category:
          "Security Guide",
        date: "Security",
      },
      {
        title:
          "AI-assisted incident investigation",
        category:
          "Artificial Intelligence",
        date: "CyberGuard AI",
      },
      {
        title:
          "Why continuous security monitoring matters",
        category:
          "Security Guide",
        date: "CyberGuard",
      },
    ];

    return (
      <>
        <PageHeader
          title={t.newsTitle}
          description="Cybersecurity information"
        />

        <div className="news-grid">
          {news.map(
            (item, index) => (
              <article
                className="news-card"
                key={index}
              >
                <div className="news-image">
                  <span>CYBER</span>
                </div>

                <div className="news-body">
                  <div className="news-meta">
                    <span>
                      {item.category}
                    </span>

                    <time>
                      {item.date}
                    </time>
                  </div>

                  <h2>{item.title}</h2>

                  <p>
                    Stay informed about
                    cybersecurity,
                    protection methods
                    and defensive
                    monitoring.
                  </p>

                  <button className="text-button">
                    Read more →
                  </button>
                </div>
              </article>
            ),
          )}
        </div>
      </>
    );
  }

  function renderProfile() {
    return (
      <>
        <PageHeader
          title={t.profileTitle}
          description="Manage your personal information"
        />

        <div className="profile-layout">
          <div className="panel profile-card">
            <div className="profile-avatar-large">
              {(user?.name || "U")
                .charAt(0)
                .toUpperCase()}
            </div>

            <h2>{user?.name || "User"}</h2>

            <p>
              {user?.email ||
                "user@example.com"}
            </p>

            <div className="profile-badge">
              <span>✓</span>
              Protected account
            </div>
          </div>

          <div className="panel">
            <div className="panel-title">
              <h2>Account information</h2>
            </div>

            <div className="form-grid">
              <label>
                <span>{t.name}</span>

                <input
                  value={
                    user?.name || ""
                  }
                  readOnly
                />
              </label>

              <label>
                <span>{t.email}</span>

                <input
                  value={
                    user?.email || ""
                  }
                  readOnly
                />
              </label>
            </div>

            <div className="account-security">
              <div>
                <strong>
                  {t.accountSecurity}
                </strong>

                <span>
                  Account protection is active.
                </span>
              </div>

              <StatusBadge value="Protected" />
            </div>

            <div className="account-security">
              <div>
                <strong>Role</strong>

                <span>
                  {user?.role || "user"}
                </span>
              </div>

              <StatusBadge value="Active" />
            </div>
          </div>
        </div>
      </>
    );
  }

  function renderSettings() {
    return (
      <>
        <PageHeader
          title={t.settingsTitle}
          description="Customize your CyberGuard AI experience"
        />

        <div className="settings-list">
          <div className="setting-row">
            <div>
              <h3>{t.language}</h3>

              <p>
                Choose application language
              </p>
            </div>

            <select
              value={language}
              onChange={(event) =>
                setLanguage(
                  event.target.value as Language,
                )
              }
            >
              <option value="UZ">
                O‘zbekcha
              </option>

              <option value="RU">
                Русский
              </option>

              <option value="EN">
                English
              </option>
            </select>
          </div>

          <div className="setting-row">
            <div>
              <h3>{t.theme}</h3>

              <p>
                {darkMode
                  ? t.darkMode
                  : t.lightMode}
              </p>
            </div>

            <button
              className={`toggle ${
                darkMode ? "on" : ""
              }`}
              onClick={() =>
                setDarkMode(
                  (value) => !value,
                )
              }
            >
              <span />
            </button>
          </div>

          <div className="setting-row">
            <div>
              <h3>{t.twoFactor}</h3>

              <p>
                Additional account protection
              </p>
            </div>

            <span className="setting-status">
              {t.enabled}
            </span>
          </div>
        </div>
      </>
    );
  }

  function renderHelp() {
    const questions = [
      "How do I start a security scan?",
      "How can I block a threat?",
      "How do I change the language?",
      "How can I check my password?",
      "How does AI Security work?",
      "Where can I see security logs?",
    ];

    return (
      <>
        <PageHeader
          title={t.helpTitle}
          description={t.helpText}
        />

        <div className="help-grid">
          {questions.map(
            (question, index) => (
              <div
                className="help-card"
                key={index}
              >
                <div className="help-icon">
                  ?
                </div>

                <h3>{question}</h3>

                <p>
                  Open the related
                  CyberGuard AI section
                  to perform this action.
                </p>

                <button
                  className="text-button"
                  onClick={() =>
                    navigate("ai")
                  }
                >
                  Learn more →
                </button>
              </div>
            ),
          )}
        </div>

        <div className="support-banner">
          <div>
            <h2>Need more help?</h2>

            <p>
              Use the AI Security assistant
              for cybersecurity questions.
            </p>
          </div>

          <button
            className="primary-button"
            onClick={() =>
              navigate("ai")
            }
          >
            Open AI Assistant
          </button>
        </div>
      </>
    );
  }

  function renderCurrentPage() {
    switch (currentPage) {
      case "dashboard":
        return renderDashboard();

      case "security":
        return renderSecurity();

      case "scan":
        return renderScan();

      case "devices":
        return renderDevices();

      case "threats":
        return renderThreats();

      case "password":
        return renderPassword();

      case "network":
        return renderNetwork();

      case "reports":
        return renderReports();

      case "ai":
        return renderAI();

      case "logs":
        return renderLogs();

      case "notifications":
        return renderNotifications();

      case "news":
        return renderNews();

      case "profile":
        return renderProfile();

      case "settings":
        return renderSettings();

      case "help":
        return renderHelp();

      default:
        return renderDashboard();
    }
  }

  if (authChecking) {
    return (
      <div className="auth-page">
        <div className="auth-background">
          <div className="auth-glow one" />
          <div className="auth-glow two" />
        </div>

        <div className="auth-card auth-loading-card">
          <div className="auth-logo">
            <div className="logo-mark">
              C
            </div>

            <div>
              <strong>CyberGuard</strong>
              <span>AI Security</span>
            </div>
          </div>

          <div className="auth-loading-icon">
            <div className="loading-spinner" />
          </div>

          <div className="auth-heading">
            <h1>Security Check</h1>

            <p>
              Sessioningiz tekshirilmoqda...
            </p>
          </div>
        </div>
      </div>
    );
  }

  if (!isLoggedIn) {
    const registrationStrength =
      getPasswordStrength(password);

    const registrationPercentage =
      Math.min(
        100,
        (registrationStrength.score / 6) * 100,
      );

    return (
      <div className="auth-page">
        <div className="auth-background">
          <div className="auth-grid" />

          <div className="auth-glow one" />
          <div className="auth-glow two" />

          <div className="auth-particle particle-one" />
          <div className="auth-particle particle-two" />
          <div className="auth-particle particle-three" />
        </div>

        <div className="auth-security-badge">
          <span className="security-dot" />
          SECURE CONNECTION
        </div>

        <div className="auth-card">
          <div className="auth-logo">
            <div className="logo-mark">
              C
            </div>

            <div>
              <strong>CyberGuard</strong>
              <span>AI Security</span>
            </div>
          </div>

          <div className="auth-heading">
            <div className="auth-heading-icon">
              {loginMode === "login"
                ? "🔐"
                : "🛡️"}
            </div>

            <h1>
              {loginMode === "login"
                ? t.welcome
                : t.createAccount}
            </h1>

            <p>{t.loginDescription}</p>
          </div>

          <form
            onSubmit={
              loginMode === "login"
                ? handleLogin
                : handleRegister
            }
          >
            {loginMode === "register" && (
              <label className="auth-field">
                <span>{t.name}</span>

                <div className="auth-input-wrapper">
                  <span className="auth-input-icon">
                    ◉
                  </span>

                  <input
                    value={name}
                    onChange={(event) => {
                      setName(
                        event.target.value,
                      );
                      setAuthError("");
                      setAuthSuccess("");
                    }}
                    placeholder={t.name}
                    autoComplete="name"
                    required
                  />
                </div>
              </label>
            )}

            <label className="auth-field">
              <span>{t.email}</span>

              <div className="auth-input-wrapper">
                <span className="auth-input-icon">
                  @
                </span>

                <input
                  type="email"
                  value={email}
                  onChange={(event) => {
                    setEmail(
                      event.target.value,
                    );
                    setAuthError("");
                    setAuthSuccess("");
                  }}
                  placeholder="example@email.com"
                  autoComplete="email"
                  required
                />
              </div>
            </label>

            <label className="auth-field">
              <span>{t.passwordLabel}</span>

              <div className="auth-input-wrapper">
                <span className="auth-input-icon">
                  🔑
                </span>

                <input
                  type={
                    showAuthPassword
                      ? "text"
                      : "password"
                  }
                  value={password}
                  onChange={(event) => {
                    setPassword(
                      event.target.value,
                    );
                    setAuthError("");
                    setAuthSuccess("");
                  }}
                  placeholder="••••••••••••"
                  autoComplete={
                    loginMode === "login"
                      ? "current-password"
                      : "new-password"
                  }
                  required
                />

                <button
                  type="button"
                  className="password-eye-button"
                  onClick={() =>
                    setShowAuthPassword(
                      (value) => !value,
                    )
                  }
                  aria-label={
                    showAuthPassword
                      ? "Hide password"
                      : "Show password"
                  }
                >
                  {showAuthPassword
                    ? "🙈"
                    : "👁"}
                </button>
              </div>
            </label>

            {loginMode === "register" &&
              password && (
                <div className="auth-password-strength">
                  <div className="auth-strength-header">
                    <span>
                      Password strength
                    </span>

                    <strong>
                      {
                        registrationStrength.label
                      }
                    </strong>
                  </div>

                  <div className="auth-strength-bar">
                    <div
                      style={{
                        width: `${registrationPercentage}%`,
                      }}
                    />
                  </div>

                  <div className="auth-password-rules">
                    <Rule
                      ok={
                        password.length >=
                        passwordPolicy.minLength
                      }
                      text={`${passwordPolicy.minLength}+ characters`}
                    />

                    <Rule
                      ok={/[A-Z]/.test(
                        password,
                      )}
                      text="Uppercase letter"
                    />

                    <Rule
                      ok={/[a-z]/.test(
                        password,
                      )}
                      text="Lowercase letter"
                    />

                    <Rule
                      ok={/[0-9]/.test(
                        password,
                      )}
                      text="Number"
                    />

                    <Rule
                      ok={/[^A-Za-z0-9]/.test(
                        password,
                      )}
                      text="Special character"
                    />
                  </div>
                </div>
              )}

            {authError && (
              <div className="auth-error">
                <span>!</span>
                {authError}
              </div>
            )}

            {authSuccess && (
              <div className="auth-success">
                <span>✓</span>
                {authSuccess}
              </div>
            )}

            <button
              type="submit"
              className="auth-submit"
              disabled={loading}
            >
              {loading ? (
                <>
                  <span className="button-spinner" />
                  Processing...
                </>
              ) : (
                <>
                  <span>
                    {loginMode === "login"
                      ? "→"
                      : "✓"}
                  </span>

                  {loginMode === "login"
                    ? t.signIn
                    : t.createAccount}
                </>
              )}
            </button>
          </form>

          <div className="auth-security-info">
            <span>✓</span>

            <div>
              <strong>
                Protected authentication
              </strong>

              <small>
                Passwords are hashed on the backend.
              </small>
            </div>
          </div>

          <div className="auth-switch">
            {loginMode === "login" ? (
              <>
                <span>{t.noAccount}</span>

                <button
                  type="button"
                  onClick={() => {
                    setLoginMode("register");
                    setAuthError("");
                    setAuthSuccess("");
                    setPassword("");
                  }}
                >
                  {t.register}
                </button>
              </>
            ) : (
              <>
                <span>{t.haveAccount}</span>

                <button
                  type="button"
                  onClick={() => {
                    setLoginMode("login");
                    setAuthError("");
                    setAuthSuccess("");
                    setPassword("");
                  }}
                >
                  {t.login}
                </button>
              </>
            )}
          </div>

          <div className="language-buttons">
            {(
              ["UZ", "RU", "EN"] as Language[]
            ).map((item) => (
              <button
                type="button"
                className={
                  language === item
                    ? "active"
                    : ""
                }
                key={item}
                onClick={() =>
                  setLanguage(item)
                }
              >
                {item}
              </button>
            ))}
          </div>

          <div className="auth-footer">
            <span>CyberGuard AI</span>
            <span>•</span>
            <span>
              Secure Cybersecurity Platform
            </span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div
      className={`app-shell ${
        darkMode ? "dark" : "light"
      }`}
    >
      <aside className="sidebar">
        <div className="sidebar-logo">
          <div className="logo-mark">
            C
          </div>

          <div>
            <strong>CyberGuard</strong>
            <span>AI Security</span>
          </div>
        </div>

        <nav className="sidebar-nav">
          {menuGroups.map((group) => (
            <div
              className="menu-group"
              key={group.key}
            >
              <div className="menu-title">
                {
                  t[
                    group.key as keyof typeof t
                  ] as string
                }
              </div>

              {group.items.map(
                ([page, label, icon]) => {
                  const pageKey =
                    page as Page;

                  const translated =
                    t[
                      pageKey as keyof typeof t
                    ];

                  return (
                    <button
                      key={page}
                      className={`menu-item ${
                        currentPage ===
                        pageKey
                          ? "active"
                          : ""
                      }`}
                      onClick={() =>
                        navigate(pageKey)
                      }
                    >
                      <span className="menu-icon">
                        {icon}
                      </span>

                      <span>
                        {typeof translated ===
                        "string"
                          ? translated
                          : label}
                      </span>

                      {pageKey ===
                        "notifications" &&
                        unreadCount > 0 && (
                          <b className="menu-badge">
                            {unreadCount}
                          </b>
                        )}
                    </button>
                  );
                },
              )}
            </div>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <button
            className="menu-item logout-button"
            onClick={() =>
              void logout()
            }
          >
            <span className="menu-icon">
              ↪
            </span>

            <span>{t.logout}</span>
          </button>

          <div className="sidebar-version">
            CyberGuard AI v2.0.0
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="mobile-brand">
            <div className="logo-mark">
              C
            </div>

            <strong>CyberGuard</strong>
          </div>

          <div className="topbar-spacer" />

          <div className="topbar-actions">
            <div className="clock">
              <span>◷</span>
              {currentTime.toLocaleTimeString()}
            </div>

            <select
              className="language-select"
              value={language}
              onChange={(event) =>
                setLanguage(
                  event.target.value as Language,
                )
              }
            >
              <option value="UZ">UZ</option>
              <option value="RU">RU</option>
              <option value="EN">EN</option>
            </select>

            <button
              className="icon-button"
              onClick={() =>
                setDarkMode(
                  (value) => !value,
                )
              }
              title={
                darkMode
                  ? t.lightMode
                  : t.darkMode
              }
            >
              {darkMode ? "☀" : "☾"}
            </button>

            <div className="notification-wrapper">
              <button
                className="icon-button notification-button"
                onClick={() =>
                  setShowNotifications(
                    (value) => !value,
                  )
                }
              >
                ♢

                {unreadCount > 0 && (
                  <span className="notification-count">
                    {unreadCount}
                  </span>
                )}
              </button>

              {showNotifications && (
                <div className="notification-dropdown">
                  <div className="dropdown-header">
                    <strong>
                      {t.notificationsTitle}
                    </strong>

                    <button
                      onClick={() =>
                        void markNotificationsRead()
                      }
                    >
                      Read all
                    </button>
                  </div>

                  {notifications
                    .slice(0, 4)
                    .map(
                      (notification) => (
                        <button
                          className="dropdown-notification"
                          key={
                            notification.id
                          }
                          onClick={() =>
                            navigate(
                              "notifications",
                            )
                          }
                        >
                          <div
                            className={`dropdown-icon ${notification.type}`}
                          >
                            {notification.type ===
                            "danger"
                              ? "!"
                              : notification.type ===
                                  "warning"
                                ? "⚠"
                                : "✓"}
                          </div>

                          <div>
                            <strong>
                              {
                                notification.title
                              }
                            </strong>

                            <span>
                              {
                                notification.message
                              }
                            </span>

                            <small>
                              {
                                notification.time
                              }
                            </small>
                          </div>
                        </button>
                      ),
                    )}

                  {notifications.length === 0 && (
                    <div className="mini-row">
                      <div className="mini-icon info">
                        i
                      </div>

                      <div className="mini-content">
                        <strong>
                          No notifications
                        </strong>

                        <span>
                          Security alerts will appear here.
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            <button
              className="user-menu"
              onClick={() =>
                navigate("profile")
              }
            >
              <div className="user-avatar">
                {(user?.name || "U")
                  .charAt(0)
                  .toUpperCase()}
              </div>

              <div className="user-info">
                <strong>
                  {user?.name || "User"}
                </strong>

                <span>
                  {user?.email}
                </span>
              </div>
            </button>
          </div>
        </header>

        <div className="content-area">
          {renderCurrentPage()}
        </div>

        <footer className="footer">
          <span>
            © 2026 CyberGuard AI. All rights reserved.
          </span>

          <span>
            AI Cybersecurity Platform
          </span>
        </footer>
      </main>
    </div>
  );
}

function PageHeader({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        <h1>{title}</h1>

        <p>{description}</p>
      </div>

      {action}
    </div>
  );
}

function StatusBadge({
  value,
}: {
  value: string;
}) {
  const normalized =
    value.toLowerCase();

  let className = "neutral";

  if (
    normalized.includes("online") ||
    normalized.includes("blocked") ||
    normalized.includes("protected") ||
    normalized.includes("secure") ||
    normalized.includes("active")
  ) {
    className =
      normalized.includes("active")
        ? "warning"
        : "success";
  } else if (
    normalized.includes("offline") ||
    normalized.includes("review") ||
    normalized.includes("attention")
  ) {
    className = "warning";
  }

  return (
    <span
      className={`status-badge ${className}`}
    >
      <i />
      {value}
    </span>
  );
}

function RiskBadge({
  value,
}: {
  value: string;
}) {
  const normalized =
    value.toLowerCase();

  const className =
    normalized === "high"
      ? "danger"
      : normalized === "medium"
        ? "warning"
        : normalized === "critical"
          ? "danger"
          : "success";

  return (
    <span
      className={`risk-badge ${className}`}
    >
      {value}
    </span>
  );
}

function SeverityBadge({
  value,
}: {
  value: string;
}) {
  const normalized =
    value.toLowerCase();

  const className =
    normalized === "critical" ||
    normalized === "high"
      ? "danger"
      : normalized === "medium"
        ? "warning"
        : "success";

  return (
    <span
      className={`severity-badge ${className}`}
    >
      {value}
    </span>
  );
}

function SecurityCard({
  icon,
  title,
  value,
  progress,
}: {
  icon: string;
  title: string;
  value: string;
  progress: number;
}) {
  return (
    <div className="security-card">
      <div className="security-card-top">
        <div className="security-card-icon">
          {icon}
        </div>

        <StatusBadge value={value} />
      </div>

      <h3>{title}</h3>

      <div className="security-progress">
        <div
          style={{
            width: `${Math.max(
              0,
              Math.min(
                100,
                progress,
              ),
            )}%`,
          }}
        />
      </div>

      <span>
        {Math.round(progress)}% protected
      </span>
    </div>
  );
}

function CheckItem({
  text,
}: {
  text: string;
}) {
  return (
    <div className="check-item">
      <span>✓</span>
      {text}
    </div>
  );
}

function Rule({
  ok,
  text,
}: {
  ok: boolean;
  text: string;
}) {
  return (
    <div
      className={
        ok
          ? "rule ok"
          : "rule"
      }
    >
      <span>{ok ? "✓" : "○"}</span>
      {text}
    </div>
  );
}

function Tip({
  text,
}: {
  text: string;
}) {
  return (
    <div className="tip-item">
      <span>✓</span>

      <p>{text}</p>
    </div>
  );
}

function Detail({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div className="detail-row">
      <span>{label}</span>

      <strong>{value}</strong>
    </div>
  );
}

function ReportCard({
  title,
  value,
  text,
}: {
  title: string;
  value: string;
  text: string;
}) {
  return (
    <div className="report-card">
      <span>{title}</span>

      <strong>{value}</strong>

      <small>{text}</small>
    </div>
  );
}

export default App;

