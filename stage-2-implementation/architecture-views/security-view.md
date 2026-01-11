# Представление безопасности (Security View)

## 1. Обзор стратегии безопасности

### 1.1 Принципы безопасности

Фитнес-социальное приложение реализует **многоуровневую стратегию безопасности**, основанную на следующих ключевых принципах:

**Zero Trust Architecture:**
- **Never trust, always verify:** Проверка всех запросов независимо от источника
- **Least privilege access:** Минимальные необходимые права для каждой сущности
- **Micro-segmentation:** Изоляция компонентов на сетевом уровне
- **Assume breach:** Проектирование с учетом компрометации компонентов

**Defense in Depth:**
- **Многоуровневая защита:** Несколько слоев безопасности для критичных активов
- **Разнообразие контролей:** Разные типы защитных механизмов на каждом уровне
- **Комплексный подход:** Сочетание preventive, detective и corrective мер
- **Непрерывный мониторинг:** Постоянное наблюдение за security событиями

### 1.2 Классификация данных и требования

**Уровни чувствительности данных:**

**Уровень 1 (Высокочувствительные):**
- **Типы данных:** Полные профили пользователей, медицинские метрики, платежная информация
- **Требования:** Шифрование end-to-end, строгий контроль доступа, полное аудирование
- **Регуляторные требования:** GDPR, HIPAA, PCI DSS

**Уровень 2 (Средняя чувствительность):**
- **Типы данных:** Геолокация тренировок, социальные взаимодействия, спортивные достижения
- **Требования:** Шифрование в покое и при передаче, ролевой доступ, ограниченное хранение
- **Регуляторные требования:** CCPA, местные законы о защите данных

**Уровень 3 (Низкая чувствительность):**
- **Типы данных:** Агрегированная статистика, публичные профили, спортивные новости
- **Требования:** Базовая аутентификация, rate limiting, общедоступный доступ
- **Регуляторные требования:** Общие стандарты безопасности

### 1.3 Security Compliance Framework

**Основные стандарты соответствия:**
- **ISO 27001:** Общая система управления информационной безопасностью
- **SOC 2 Type II:** Контроли безопасности, доступности, целостности, конфиденциальности
- **GDPR:** Защита данных европейских пользователей
- **CCPA:** Права пользователей Калифорнии
- **HIPAA:** Обработка медицинских данных (при подключении медицинских устройств)

**Регулярные аудиты:**
- **Internal audits:** Ежеквартальные проверки внутренней командой безопасности
- **External audits:** Ежегодные проверки независимыми организациями
- **Penetration testing:** Два раза в год тестирование на проникновение
- **Vulnerability assessments:** Ежемесячное сканирование на уязвимости

- ## 2. Идентификация и управление доступом

### 2.1 Аутентификация пользователей

**Многофакторная аутентификация (MFA):**
- **Для всех пользователей:** Рекомендуемая, но не обязательная
- **Для premium пользователей:** Обязательная MFA
- **Для администраторов:** Обязательная hardware/software MFA
- **Методы аутентификации:**
  - **Основной:** Мобильное приложение (TOTP)
  - **Резервный:** SMS/Email коды
  - **Альтернативный:** Биометрическая аутентификация (Face ID, Touch ID)

**Управление сессиями:**
- **Длительность сессии:** 30 дней для trusted устройств, 24 часа для новых
- **Token refresh:** Automatic refresh с validation предыдущего токена
- **Concurrent sessions:** До 5 одновременных сессий на пользователя
- **Session termination:** При смене пароля, по запросу пользователя, при подозрительной активности

### 2.2 Авторизация и управление правами

**Ролевая модель доступа (RBAC):**

**Пользовательские роли:**
- **Free User:** Базовый доступ к основным функциям
- **Premium User:** Расширенные возможности, аналитика, персонализация
- **Pro Athlete:** Профессиональные инструменты, интеграция с тренерами
- **Team Admin:** Управление командой, групповые статистики

**Системные роли:**
- **Viewer:** Только чтение системных данных
- **Editor:** Редактирование контента, управление пользователями
- **Admin:** Полный доступ к управлению системой
- **Auditor:** Только доступ к логам и аудиторским записям

**Attribute-Based Access Control (ABAC):**
- **Контекстуальные правила:** Доступ на основе времени, местоположения, устройства
- **Динамические политики:** Автоматическая адаптация прав на основе поведения
- **Ресурсные атрибуты:** Чувствительность данных, ownership, классификация

### 2.3 Управление идентификацией

**Identity Provider (IdP):**
- **Основной:** Собственный Identity Service на базе OAuth 2.0/OpenID Connect
- **Интеграции:** Социальные сети (для упрощенной регистрации)
- **Enterprise:** SAML 2.0 для корпоративных клиентов
- **Federation:** Cross-domain identity federation для партнеров

**Управление жизненным циклом учетных записей:**
- **Onboarding:** Верификация email/телефона, начальная настройка безопасности
- **Maintenance:** Регулярное обновление паролей, перевыпуск токенов
- **Offboarding:** Обеспечение удаления данных по запросу (GDPR Right to be Forgotten)
- **Account recovery:** Многоуровневая процедура восстановления доступа

## 3. Защита данных

### 3.1 Шифрование данных

**Шифрование в покое (At-rest encryption):**
- **Базовый уровень:** Cloud provider managed encryption для всех хранилищ
- **Дополнительный уровень:** Customer-managed keys (CMK) для PII данных
- **Application-level encryption:** Дополнительное шифрование чувствительных полей
- **Key management:** Централизованное управление через AWS KMS/GCP KMS/Azure Key Vault

**Шифрование при передаче (In-transit encryption):**
- **TLS 1.3:** Для всех внешних и внутренних коммуникаций
- **Certificate management:**
  - **Public endpoints:** Let's Encrypt с автоматическим обновлением
  - **Internal services:** Private PKI с короткоживущими сертификатами
- **Perfect Forward Secrecy:** Ephemeral ключи для каждой TLS сессии
- **Certificate pinning:** Для мобильных приложений и критичных сервисов

### 3.2 Маскирование и анонимизация данных

**Data masking в production:**
- **Динамическое маскирование:** В реальном времени для неавторизованных запросов
- **Статическое маскирование:** Для тестовых и development сред
- **Токенизация:** Замена чувствительных данных токенами
- **Format-preserving encryption:** Сохранение формата для legacy систем

**Анонимизация для аналитики:**
- **Pseudonymization:** Замена идентификаторов псевдонимами
- **Generalization:** Укрупнение данных (регион вместо точного местоположения)
- **Suppression:** Удаление редких комбинаций для предотвращения деанонимизации
- **Differential privacy:** Добавление статистического шума для агрегированных данных

### 3.3 Управление ключами шифрования

**Key Management Service (KMS):**
- **Геораспределенность:** Ключи хранятся в регионе данных
- **Автоматическая ротация:** Ежегодная для CMK, ежеквартальная для data keys
- **Access policies:** Строгий контроль доступа к операциям с ключами
- **Audit logging:** Полная трассировка всех операций с ключами

**Key lifecycle management:**
- **Generation:** С использованием certified hardware security modules
- **Distribution:** Secure channel с mutual TLS аутентификацией
- **Storage:** Раздельное хранение ключей и данных
- **Destruction:** Secure deletion с multiple overwrites

- ## 4. Безопасность приложения

### 4.1 Защита API

**API Gateway Security:**
- **Authentication:** JWT tokens, API keys для партнеров
- **Rate limiting:** На уровне пользователя, IP, региона
- **Request validation:** Schema validation, input sanitization
- **API versioning:** Поддержка устаревших версий с security patches

**OAuth 2.0/OpenID Connect:**
- **Authorization flows:** Authorization Code для веба, Implicit для мобильных приложений
- **Token types:** Access tokens (короткоживущие), Refresh tokens (долгоживущие)
- **Token binding:** Привязка токенов к устройству, сессии
- **Token revocation:** Немедленная инвалидация при компрометации

**API Security Testing:**
- **Static analysis:** Проверка кода на уязвимости в CI/CD
- **Dynamic analysis:** Automated security scanning в staging
- **Manual testing:** Регулярные penetration tests API endpoints
- **Fuzzing:** Автоматическое тестирование с некорректными данными

### 4.2 Защита мобильных приложений

**Mobile App Security:**
- **Code obfuscation:** Защита от reverse engineering
- **Tamper detection:** Обнаружение изменений в runtime
- **Certificate pinning:** Привязка к конкретным сертификатам сервера
- **Secure storage:** Keychain/iOS Keystore, Android Keystore

**Device Security:**
- **Root/jailbreak detection:** Блокировка на скомпрометированных устройствах
- **Biometric integration:** Face ID, Touch ID, fingerprint authentication
- **Device attestation:** Проверка подлинности устройства
- **Remote wipe:** Удаление данных при потере устройства

### 4.3 Web Application Firewall (WAF)

**WAF Configuration:**
- **OWASP Top 10 protection:** SQL injection, XSS, CSRF, etc.
- **Custom rules:** Защита от специфичных атак на фитнес-приложение
- **Rate limiting:** Защита от brute force и DoS атак
- **Bot management:** Обнаружение и блокировка malicious ботов

**Managed Rule Sets:**
- **Core rule set:** Базовые правила для common attacks
- **Platform-specific rules:** Правила для конкретных технологий
- **IP reputation lists:** Блокировка известных malicious IP
- **Geo-blocking:** Ограничение доступа из проблемных регионов

## 5. Сетевая безопасность

### 5.1 Сетевая сегментация

**Micro-segmentation:**
- **Service-level segmentation:** Изоляция микросервисов
- **Environment segmentation:** Разделение production, staging, development
- **Data tier isolation:** Отдельные сегменты для баз данных
- **Management plane isolation:** Выделенная сеть для управления

**Network Security Groups (NSG):**
- **Zero-trust policies:** Deny by default, разрешения по необходимости
- **Least privilege:** Минимальные необходимые порты и протоколы
- **Dynamic rules:** Автоматическая адаптация на основе threat intelligence
- **Logging and monitoring:** Полная трассировка сетевого трафика

### 5.2 DDoS Protection

**Multi-layered DDoS Protection:**
- **Edge protection:** Cloud-based scrubbing centers
- **Network layer protection:** Rate limiting, blackhole routing
- **Application layer protection:** WAF, bot management
- **Infrastructure resilience:** Автоматическое масштабирование под атаку

**DDoS Response Plan:**
- **Detection:** Automated anomaly detection
- **Mitigation:** Автоматическое включение защиты
- **Communication:** Уведомление пользователей о проблемах
- **Post-attack analysis:** Анализ атаки и улучшение защиты

### 5.3 VPN и безопасный доступ

**Remote Access VPN:**
- **Для администраторов:** Client-based VPN с MFA
- **Site-to-site VPN:** Для подключения партнеров и корпоративных клиентов
- **Zero Trust Network Access (ZTNA):** Application-level доступ без full network access
- **Browser-based access:** Для emergency situations

**VPN Security:**
- **Strong encryption:** AES-256-GCM для данных, SHA-384 для аутентификации
- **Perfect Forward Secrecy:** Ephemeral ключи для каждой сессии
- **Split tunneling:** Только необходимый трафик через VPN
- **Session monitoring:** Обнаружение anomalous behavior

## 6. Безопасность контейнеров и Kubernetes

### 6.1 Container Security

**Image Security:**
- **Base images:** Минималистичные образы из trusted sources
- **Vulnerability scanning:** Automated scanning в CI/CD pipeline
- **Image signing:** Digital signatures для проверки целостности
- **Immutable images:** Запрет модификации в runtime

**Runtime Security:**
- **Resource constraints:** CPU/Memory limits, read-only root filesystems
- **Security contexts:** Non-root users, dropping capabilities
- **Secrets management:** External secrets providers, encrypted volumes
- **Runtime protection:** Behavioral monitoring, anomaly detection

### 6.2 Kubernetes Security

**Cluster Hardening:**
- **RBAC:** Минимальные права для service accounts
- **Network policies:** Изоляция трафика между namespaces
- **Pod security policies:** Security context constraints
- **Audit logging:** Comprehensive audit trail всех действий

**Supply Chain Security:**
- **Software Bill of Materials (SBOM):** Транспарентность зависимостей
- **Provenance tracking:** Отслеживание происхождения всех компонентов
- **Vulnerability management:** Автоматическое обновление уязвимых компонентов
- **Compliance scanning:** Проверка на соответствие security policies

- ## 7. Мониторинг безопасности и реагирование на инциденты

### 7.1 Security Information and Event Management (SIEM)

**Централизованный сбор логов:**
- **Источники данных:** CloudTrail, VPC Flow Logs, Kubernetes audit logs, application logs
- **Нормализация:** Единый формат для всех источников данных
- **Корреляция:** Выявление сложных атак через multiple источники
- **Retention policies:** 90 дней для оперативного анализа, 1+ год для compliance

**Threat Detection:**
- **Signature-based:** Известные паттерны атак
- **Anomaly-based:** Отклонения от normal behavior
- **Machine learning:** Predictive threat detection
- **Threat intelligence feeds:** Обновления о новых угрозах

### 7.2 Инцидент-ответ (Incident Response)

**Incident Response Plan:**
- **Определение инцидентов:** Классификация по severity levels
- **Response team:** Назначенные роли и обязанности
- **Коммуникация:** Internal и external communication plans
- **Восстановление:** Процедуры восстановления нормальной работы

**Этапы обработки инцидента:**
1. **Подготовка:** Training, tools, documentation
2. **Обнаружение:** Monitoring, alerting, reporting
3. **Сдерживание:** Изоляция affected systems
4. **Устранение:** Удаление threat, восстановление integrity
5. **Восстановление:** Возврат к normal operations
6. **Уроки:** Post-incident review, improvement planning

### 7.3 Forensics и расследования

**Digital Forensics:**
- **Сбор доказательств:** Chain of custody, integrity preservation
- **Анализ памяти:** Memory dumps для обнаружения advanced threats
- **Анализ дисков:** File system analysis, deleted file recovery
- **Сетевая forensic:** Packet capture analysis, network traffic reconstruction

**Расследование инцидентов:**
- **Root cause analysis:** Определение первопричины инцидента
- **Impact assessment:** Оценка ущерба для бизнеса и пользователей
- **Regulatory reporting:** Обязательные отчеты регуляторам
- **Legal considerations:** Подготовка для potential legal actions

## 8. Compliance и аудит

### 8.1 Continuous Compliance

**Automated Compliance Checks:**
- **Infrastructure as Code scanning:** Проверка Terraform/CloudFormation templates
- **Runtime compliance:** Continuous monitoring of running systems
- **Configuration management:** Enforcement of security baselines
- **Policy as Code:** Автоматическое enforcement правил безопасности

**Compliance Frameworks:**
- **Регулярные отчеты:** Automated generation of compliance reports
- **Evidence collection:** Автоматический сбор evidence для аудитов
- **Remediation workflows:** Automated ticketing и tracking исправлений
- **Audit trails:** Immutable logs для всех security-relevant действий

### 8.2 Третьи стороны и supply chain безопасность

**Vendor Risk Management:**
- **Security assessments:** Оценка безопасности third-party providers
- **Contractual requirements:** Security obligations в контрактах
- **Continuous monitoring:** Ongoing assessment of vendor security
- **Incident notification:** Requirements для reporting security incidents

**Software Supply Chain Security:**
- **Dependency scanning:** Проверка third-party libraries на уязвимости
- **Build integrity:** Verification of build process integrity
- **Deployment verification:** Signature verification of deployment artifacts
- **Provenance tracking:** End-to-end tracking of software components

## 9. Security Awareness и training

### 9.1 Программа обучения безопасности

**Для разработчиков:**
- **Secure coding training:** OWASP Top 10, common vulnerabilities
- **Code review guidelines:** Security-focused code reviews
- **Threat modeling:** Identification и mitigation of security risks
- **Security champions:** Назначенные security experts в командах

**Для операторов:**
- **Incident response training:** Практические учения по обработке инцидентов
- **Security tooling:** Effective use of security monitoring tools
- **Configuration management:** Secure configuration of systems
- **Compliance requirements:** Understanding of regulatory obligations

### 9.2 Security Culture

**Promoting Security Culture:**
- **Leadership commitment:** Активная поддержка от руководства
- **Recognition programs:** Награды за security contributions
- **Transparent communication:** Open discussion of security issues
- **Continuous improvement:** Regular feedback и improvement cycles

**Security Metrics:**
- **Awareness metrics:** Participation in training programs
- **Behavior metrics:** Adoption of security best practices
- **Outcome metrics:** Reduction in security incidents
- **Maturity metrics:** Progression through security maturity levels

## 10. Будущие инициативы по безопасности

### 10.1 Emerging Threats и адаптация

**Подготовка к новым угрозам:**
- **Threat intelligence:** Мониторинг emerging threats в индустрии
- **Red team exercises:** Simulation of advanced persistent threats
- **Security research:** Partnership с security research community
- **Technology evaluation:** Оценка новых security technologies

**Continuous Improvement:**
- **Security roadmap:** План улучшений на 12-24 месяца
- **Budget planning:** Выделение ресурсов для security initiatives
- **Industry collaboration:** Participation in security communities
- **Regulatory adaptation:** Подготовка к новым regulatory requirements

### 10.2 Privacy by Design

**Privacy Enhancing Technologies:**
- **Differential privacy:** Для агрегированной аналитики
- **Homomorphic encryption:** Для secure computations на encrypted данных
- **Federated learning:** Для training ML моделей без centralizing данных
- **Privacy-preserving analytics:** Analytics без раскрытия индивидуальных данных

**User Privacy Controls:**
- **Privacy dashboard:** Прозрачность и контроль для пользователей
- **Data portability:** Easy export of user data
- **Consent management:** Granular consent для разных типов обработки данных
- **Privacy defaults:** Privacy-friendly настройки по умолчанию

## 11. Безопасность в контексте DDD (DDD Security Context)

### 11.1 Ограниченные контексты и изоляция безопасности

**Принцип безопасности по контекстам:**

- **Изолированные политики безопасности:** Каждый ограниченный контекст имеет свои security boundaries
- **Контекст-специфичные требования:** Разные уровни защиты для разных доменных областей
- **Микросегментация:** Сетевые политики соответствуют границам ограниченных контекстов

**Распределение ответственности:**

**Identity & Access Context:**

- **Основная ответственность:** Аутентификация, авторизация, управление учетными данными
- **Security требования:** MFA для администраторов, строгая валидация паролей, защита PII
- **Изоляция:** Выделенные security groups, отдельные политики доступа к БД
- **Комплаенс:** GDPR (право на забвение), CCPA, локальные законы о защите данных

**Workout Tracking Context:**

- **Основная ответственность:** Защита телеметрии, геолокационных данных, медицинских метрик
- **Security требования:** Шифрование медицинских данных (HIPAA), контроль доступа к реальному времени
- **Изоляция:** Отдельный кластер для обработки чувствительных данных
- **Комплаенс:** HIPAA (при подключении медицинских устройств), анонимизация геоданных

**Social Graph Context:**

- **Основная ответственность:** Защита социальных связей, приватность взаимодействий
- **Security требования:** Контроль видимости (friends-only, public), защита от злоупотреблений
- **Изоляция:** Графовая БД с дополнительным шифрованием связей
- **Комплаенс:** Контроль согласия на публикацию данных, защита от stalkerware

**Gamification Context:**

- **Основная ответственность:** Целостность игровых механик, защита от читерства
- **Security требования:** Валидация достижений, защита лидербордов, аудит начислений
- **Изоляция:** Rate limiting на операции, проверка аномалий в поведении
- **Комплаенс:** Защита от манипуляций в соревнованиях, прозрачность правил

**Inventory & Commerce Context:**

- **Основная ответственность:** Защита коммерческих данных, рекомендательных алгоритмов
- **Security требования:** PCI DSS для платежей, защита персональных предпочтений
- **Изоляция:** Сегментация от основной социальной функциональности
- **Комплаенс:** PCI DSS, защита от недобросовестного маркетинга

### 11.2 Межконтекстная безопасность и коммуникация

**Безопасная коммуникация между контекстами:**

**Доменные события (Domain Events):**

- **Шифрование событий:** Все события шифруются при передаче между контекстами
- **Подпись событий:** Digital signature для проверки источника и целостности
- **Валидация потребителей:** Авторизация потребителей событий перед обработкой
- **Аудит потока событий:** Полная трассировка распространения событий
- **Схемы версионирования:** Поддержка обратной совместимости при изменении форматов

**API Gateway для межконтекстного взаимодействия:**

- **Service-to-service аутентификация:** Mutual TLS между сервисами разных контекстов
- **Контекст-специфичные политики:** Rate limiting, quotas, access controls по контекстам
- **Трансформация запросов:** Адаптация форматов данных между контекстами
- **Агрегация безопасности:** Централизованная проверка для сложных операций
- **Circuit breakers:** Защита от каскадных отказов при недоступности контекстов

**Шлюзы доступа (API Gateways по контекстам):**

- **Внешний API Gateway:** Для публичных API (мобильные приложения, веб)
- **Внутренний API Gateway:** Для межконтекстной коммуникации
- **Контекстные прокси:** Для интеграции с legacy-системами компании
- **Антикоррупционные слои:** Защита от проникновения устаревших моделей безопасности

### 11.3 Управление секретами по ограниченным контекстам

**Иерархия секретов:**

**Уровень 1: Глобальные секреты (Global Secrets)**

- **Примеры:** Корневые сертификаты CA, master encryption keys
- **Доступ:** Только security team и critical infrastructure
- **Хранение:** Hardware Security Modules (HSM), изолированные хранилища
- **Ротация:** Ручная ротация с многоэтапным approval процессом

**Уровень 2: Контекстные секреты (Context Secrets)**

- **Примеры:** API keys для внешних сервисов, пароли БД контекста, JWT signing keys
- **Доступ:** Только сервисы соответствующего ограниченного контекста
- **Хранение:** Контекст-специфичные namespaces в HashiCorp Vault/AWS Secrets Manager
- **Ротация:** Автоматическая ротация каждые 90 дней

**Уровень 3: Сервисные секреты (Service Secrets)**

- **Примеры:** Временные токены доступа, connection strings для зависимостей
- **Доступ:** Только конкретный микросервис
- **Хранение:** Kubernetes Secrets с ограниченным доступом по namespace
- **Ротация:** Динамическая генерация при каждом развертывании

**Автоматическая ротация секретов:**

- **По расписанию:** Регулярная ротация (30-90 дней в зависимости от типа)
- **По событиям:** Немедленная ротация при подозрении на компрометацию
- **Grace period:** Поддержка старых и новых версий во время перехода
- **Аудит ротации:** Полное логирование всех операций с секретами
- **Откат ротации:** Процедуры emergency rollback при проблемах

### 11.4 Аудит и соответствие в DDD-архитектуре

**Контекст-специфичный аудит:**

**Аудит доменных операций:**

- **Регистрация всех команд:** Кто, когда, какую команду выполнил в каждом контексте
- **Аудит агрегатов:** Изменения состояния агрегатов, включая старые и новые значения
- **Трассировка пользовательских действий:** End-to-end отслеживание действий через несколько контекстов
- **Привязка к бизнес-процессам:** Аудит в терминах домена, а не технических операций
- **Корреляция событий:** Связывание технических логов с бизнес-событиями

**Compliance по контекстам:**

- **GDPR compliance:** Identity & Access Context отвечает за права пользователей
- **HIPAA compliance:** Workout Tracking Context отвечает за медицинские данные
- **PCI DSS compliance:** Inventory & Commerce Context отвечает за платежные операции
- **Локальные регуляторы:** Соответствие требованиям каждой страны присутствия
- **Индустриальные стандарты:** Соответствие спортивным и health-tech стандартам

**Отчетность и мониторинг:**

- **Контекст-специфичные дашборды:** Мониторинг security метрик по каждому контексту
- **Автоматические отчеты:** Генерация compliance отчетов для регуляторов
- **Аномальное поведение:** Выявление подозрительной активности в рамках контекста
- **Security scoring:** Оценка безопасности каждого ограниченного контекста
- **Тренды и аналитика:** Анализ security метрик для выявления долгосрочных трендов

**Интеграция с бизнес-процессами:**

- **Security в пользовательских сценариях:** Защита данных в рамках use cases
- **Приватность по дизайну:** Встроенная приватность в каждую доменную операцию
- **Прозрачность для пользователей:** Возможность аудита собственных данных
- **Автоматизированные compliance checks:** Проверки в рамках бизнес-логики

## Резюме стратегии безопасности

Безопасность фитнес-социального приложения построена на комплексном подходе, объединяющем:

1. **Zero Trust Architecture:** Fundamental принцип "никому не доверять"
2. **Defense in Depth:** Многоуровневая защита critical assets
3. **Data-centric security:** Защита на уровне данных, а не только perimeter
4. **Continuous monitoring:** Реальное время detection и response
5. **Automated compliance:** Continuous compliance через Policy as Code
6. **Security by Design:** Встроенная безопасность на всех этапах lifecycle
7. **Privacy by Default:** Защита приватности пользователей как основной приоритет
8. **Context-aware security:** Специфичные политики безопасности для каждого ограниченного контекста
9. **DDD-aligned protection:** Защита, соответствующая доменным границам и бизнес-процессам

Данная стратегия обеспечивает защиту миллионов пользователей, их персональных и медицинских данных, соответствие международным стандартам и регуляторным требованиям, а также устойчивость к современным и emerging угрозам.
