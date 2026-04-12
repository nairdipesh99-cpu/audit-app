ss"""80 — IAM Audit Tool engine. All audit logic lives here. Pages import from this file."""

import pandas as pd
from thefuzz import fuzz
import io, json, base64, re, random
from datetime import datetime, date, timedelta

# ─────────────────────────────────────────────────────────────────────────────
#  POLICY CONSTANTS  (sidebar overrides these at runtime)
# ─────────────────────────────────────────────────────────────────────────────
DORMANT_DAYS         = 90
PASSWORD_EXPIRY_DAYS = 90
FUZZY_THRESHOLD      = 88
MAX_SYSTEMS          = 3


# ─────────────────────────────────────────────────────────────────────────────
#  SEMANTIC INTELLIGENCE — department and access level normalisation
#  Maps real-world naming variations to canonical forms used in rules.
#  Add new variations here as you encounter them from client data.
# ─────────────────────────────────────────────────────────────────────────────

DEPT_SYNONYMS = {

    # ── FINANCE ──────────────────────────────────────────────────────────────
    "Finance": [
        # Core names
        "finance","finance department","finance dept","finance team",
        "finance division","finance function","finance group","finance unit",
        "finance & accounting","finance and accounting","finance/accounting",
        "financial","financial department","financial services",
        "financial management","financial operations","financial control",
        "financial controller","financial controllers","financial reporting",
        "financial planning","financial planning & analysis",
        "financial planning and analysis","fp&a","fpa",
        # Accounting variations
        "accounting","accounting department","accounts","accounts department",
        "accounts team","accounts division","accountancy","accountants",
        "accounts & finance","accounts and finance","finance & accounts",
        # Specific sub-functions
        "accounts payable","ap","accounts payable department","ap team",
        "accounts receivable","ar","accounts receivable department","ar team",
        "payroll","payroll department","payroll team","payroll & benefits",
        "payroll and benefits","salary","salaries","compensation",
        "compensation & benefits","compensation and benefits","c&b","cb",
        "total rewards","total reward","benefits","benefits administration",
        "treasury","treasury department","treasury management","treasury team",
        "treasury & cash management","cash management","liquidity management",
        "tax","taxation","tax department","tax team","indirect tax","direct tax",
        "vat","corporate tax","transfer pricing",
        "audit","internal audit","internal audit department","audit team",
        "finance audit","financial audit","external audit liaison",
        "management accounts","management accounting","cost accounting",
        "cost control","cost management","budgeting","budget","budgets",
        "planning","planning & budgeting","planning and budgeting",
        "forecasting","commercial finance","commercial","business finance",
        "group finance","central finance","group accounting",
        "shared services","shared services finance","finance shared services",
        "finance ops","finance operations","finance & operations",
        "billing","billing department","billing team","collections",
        "credit control","credit management","revenue","revenue accounting",
        "revenue recognition","statutory reporting","group reporting",
        "investor relations","finance business partner","finance bp",
        "gl","general ledger","fixed assets","asset management finance",
        "intercompany","reconciliation","financial risk","credit risk finance",
        # ERP system names often used as dept
        "sap finance","oracle finance","netsuite","sage","xero","quickbooks",
        "dynamics finance","d365 finance",
    ],

    # ── INFORMATION TECHNOLOGY ────────────────────────────────────────────────
    "IT": [
        # Core IT names
        "it","it department","it dept","it team","it division",
        "it function","it group","it services","it service",
        "information technology","information technology department",
        "information technology services","information technology division",
        "information systems","is","mis","management information systems",
        "technology","technology department","technology services",
        "technology team","technology division","technology group",
        "tech","tech team","tech department","tech services","tech division",
        # Operations
        "it operations","it ops","it operations & support","ito",
        "infrastructure","infrastructure & operations","i&o",
        "it infrastructure","infrastructure team","infrastructure department",
        "network","networking","network team","network & infrastructure",
        "network operations","noc","network operations centre",
        "systems","systems team","systems administration","sysadmin",
        "it support","support team","technical support","tech support",
        "helpdesk","help desk","service desk","it service desk","itsm",
        "end user computing","euc","desktop support","deskside support",
        # Development
        "software development","software engineering","development",
        "it development","application development","app development",
        "software","software team","engineering","it engineering",
        "devops","dev ops","development operations","platform",
        "platform engineering","platform team","sre","site reliability",
        "site reliability engineering","cloud","cloud team","cloud services",
        "cloud operations","cloud & devops","cloud engineering",
        "backend","frontend","full stack","mobile development","mobile",
        # Security
        "security","it security","information security","infosec",
        "cyber","cyber security","cybersecurity","it security team",
        "security operations","soc","security operations centre",
        "vulnerability management","penetration testing","pen test",
        "identity & access management","iam","identity management",
        "privileged access management","pam","endpoint security",
        "security engineering","security architecture","ciso office",
        # Architecture and strategy
        "architecture","it architecture","enterprise architecture","ea",
        "solution architecture","technical architecture",
        "it strategy","digital strategy","technology strategy",
        "digital","digital team","digital services","digital transformation",
        "digital & technology","digital and technology","d&t","dt",
        # Data infrastructure
        "data engineering","data infrastructure","data platform",
        "bi","business intelligence","data warehouse","datawarehouse",
        "etl","data integration","reporting & analytics it",
        # Other IT
        "it procurement","software licensing","asset management it",
        "it asset management","itam","change management it",
        "release management","it project management","it pmo",
        "vendor management it","it vendor management",
        "it governance","it compliance","it risk","grc it",
    ],

    # ── HUMAN RESOURCES ───────────────────────────────────────────────────────
    "HR": [
        # Core HR names
        "hr","hr department","hr dept","hr team","hr division",
        "hr function","hr group","human resources","human resources department",
        "human resources team","human resources division",
        "human resource","human resource department",
        "people","people team","people department","people division",
        "people function","people & culture","people and culture",
        "people operations","people ops","people & organisation",
        "people and organisation","people & organizational development",
        # Talent and recruitment
        "talent","talent team","talent management","talent acquisition",
        "talent & development","talent and development",
        "recruitment","recruitment team","recruitment department",
        "resourcing","resourcing team","talent resourcing",
        "staffing","staffing team","workforce","workforce planning",
        "headcount","headcount planning",
        # Learning and development
        "learning & development","learning and development","l&d","ld",
        "learning","learning team","training","training department",
        "training & development","training and development","t&d","td",
        "organisational development","organizational development","od",
        "organisation development","leadership development",
        "capability development","people development","talent development",
        # Employee relations and experience
        "employee relations","er","employment relations",
        "employee experience","employee engagement","engagement",
        "culture","culture team","dei","diversity equity inclusion",
        "diversity & inclusion","diversity and inclusion","d&i",
        "wellbeing","employee wellbeing","wellness","health & wellbeing",
        # HR operations
        "hr operations","hr ops","hris","hr information systems",
        "hrms","hr management systems","hr shared services",
        "people analytics","hr analytics","workforce analytics",
        "compensation & benefits","compensation and benefits","c&b","cb",
        "total rewards","total reward","benefits","benefits administration",
        "payroll","payroll team","payroll department",
        "hr business partner","hrbp","hr bp","business partner hr",
        "hr generalist","generalist hr",
        # Compliance
        "hr compliance","employment law","er legal","hr legal",
        "immigration","visa","right to work",
    ],

    # ── SALES ─────────────────────────────────────────────────────────────────
    "Sales": [
        # Core sales
        "sales","sales department","sales team","sales division",
        "sales function","sales group","sales & marketing",
        "sales and marketing","commercial","commercial team",
        "commercial department","commercial division",
        "business development","bd","biz dev","business dev",
        # Inside and field
        "inside sales","inside sales team","field sales","field sales team",
        "direct sales","indirect sales","outbound sales","inbound sales",
        "telesales","telephone sales","digital sales","online sales",
        "e-commerce sales","ecommerce sales",
        # Enterprise and segments
        "enterprise sales","enterprise team","mid-market sales",
        "smb sales","small business sales","corporate sales",
        "strategic sales","national accounts","national sales",
        "regional sales","regional team","territory sales",
        "international sales","global sales","export sales",
        # Account management
        "account management","account managers","key accounts",
        "key account management","strategic accounts","named accounts",
        "global accounts","major accounts","national accounts",
        # Revenue and growth
        "revenue","revenue team","revenue operations","revops","rev ops",
        "go to market","gtm","growth","growth team",
        "new business","new business development","new logo",
        # Channel and partnerships
        "channel","channel sales","channel team","channel management",
        "partner","partners","partnerships","alliance","alliances",
        "partner management","channel & alliances",
        "reseller","resellers","distributor","distribution",
        # Pre-sales
        "pre-sales","presales","pre sales","solution consulting",
        "sales engineering","sales engineers","technical sales",
        "solutions","solutions team",
    ],

    # ── MARKETING ─────────────────────────────────────────────────────────────
    "Marketing": [
        # Core marketing
        "marketing","marketing department","marketing team","marketing division",
        "marketing function","marketing group","marketing & comms",
        "marketing and communications","marketing & communications",
        "brand","brand team","brand marketing","brand management",
        "brand & marketing","branding","brand & comms",
        # Digital marketing
        "digital marketing","digital marketing team","online marketing",
        "performance marketing","growth marketing","d2c marketing",
        "paid media","paid search","ppc","sem","seo","organic search",
        "social media","social media marketing","social","community",
        "community management","influencer","influencer marketing",
        "affiliate","affiliate marketing","programmatic","display advertising",
        # Content and creative
        "content","content team","content marketing","content strategy",
        "creative","creative team","creative services","design",
        "graphic design","brand design","marketing design",
        "copywriting","copy","editorial","publications",
        "video","video production","studio","production",
        # Communications
        "communications","comms","corporate communications","corp comms",
        "pr","public relations","media relations","press","press office",
        "external communications","internal communications",
        "investor communications","stakeholder communications",
        "events","events team","event management","conferences",
        "experiential","field marketing",
        # Product marketing
        "product marketing","pmm","product marketing management",
        "go to market marketing","gtm marketing","launch",
        # Demand generation
        "demand generation","demand gen","lead generation","lead gen",
        "campaigns","campaign management","campaign team",
        "marketing operations","marketing ops","mops","marops",
        "crm marketing","lifecycle marketing","retention marketing",
        "email marketing","marketing automation",
    ],

    # ── OPERATIONS ────────────────────────────────────────────────────────────
    "Operations": [
        # Core operations
        "operations","ops","operations department","operations team",
        "operations division","business operations","biz ops","bizops",
        "operational","operational excellence","ops excellence",
        # Supply chain
        "supply chain","supply chain management","scm","supply chain team",
        "supply chain & operations","procurement & operations",
        "demand planning","supply planning","inventory","inventory management",
        "stock management","materials management","materials",
        # Logistics
        "logistics","logistics team","logistics department","logistics & ops",
        "logistics & operations","logistics and operations",
        "distribution","distribution centre","dc","warehouse",
        "warehousing","warehouse operations","fulfillment","fulfilment",
        "dispatch","shipping","transport","transportation","fleet",
        "fleet management","fleet operations","last mile","delivery",
        # Manufacturing
        "manufacturing","manufacturing operations","production","production team",
        "production operations","assembly","assembly operations","plant",
        "plant operations","factory","factory operations","workshop",
        "fabrication","process engineering","manufacturing engineering",
        # Quality
        "quality","quality assurance","qa","quality control","qc",
        "quality management","quality operations","testing","test",
        "quality & safety","hseq","health safety environment quality",
        # Facilities and property
        "facilities","facilities management","facilities team","fm",
        "property","property management","real estate","estates",
        "building management","office management","workplace",
        "workplace services","workspace","environment","site management",
        # Continuous improvement
        "continuous improvement","ci","lean","lean operations","six sigma",
        "process improvement","process excellence","transformation",
        "operational transformation","business transformation","change",
        # Field operations
        "field operations","field ops","field services","field service",
        "field engineering","installation","maintenance","technical operations",
    ],

    # ── PROCUREMENT ───────────────────────────────────────────────────────────
    "Procurement": [
        # Core procurement
        "procurement","procurement department","procurement team",
        "procurement division","procurement function","procurement group",
        "purchasing","purchasing department","purchasing team","buying",
        "buying team","buyers","commercial procurement",
        # Sourcing
        "sourcing","strategic sourcing","sourcing team","sourcing & procurement",
        "category management","category","categories","category team",
        "indirect procurement","direct procurement","global procurement",
        # Supply management
        "supply management","supplier management","vendor management",
        "supply base management","third party management","tpm",
        # Contracts
        "contracts","contracts management","contract management",
        "contract administration","commercial contracts",
        "procurement & contracts","procurement and contracts",
        # Procure to pay
        "p2p","procure to pay","purchase to pay","p2p team",
        "invoice processing","purchase orders","po management",
        # Spend management
        "spend management","spend analysis","spend analytics",
        "cost reduction","savings","procurement savings",
        # Other
        "logistics procurement","it procurement","capex procurement",
        "facilities procurement","services procurement",
    ],

    # ── LEGAL ─────────────────────────────────────────────────────────────────
    "Legal": [
        # Core legal
        "legal","legal department","legal team","legal division",
        "legal function","legal group","legal services","legal & compliance",
        "legal and compliance","general counsel","gc","office of general counsel",
        "ogc","legal counsel","in-house legal","corporate legal",
        # Legal sub-functions
        "contracts","contract management","commercial contracts legal",
        "company secretarial","company secretary","secretarial","cosec",
        "corporate secretarial","board secretariat","governance secretarial",
        "corporate law","corporate affairs","corporate governance",
        "litigation","dispute resolution","employment law","labour law",
        "intellectual property","ip","ip management","ip team",
        "trademarks","patents","copyright","licensing legal",
        "privacy","data privacy","data protection legal","gdpr legal",
        # Regulatory
        "regulatory","regulatory affairs","regulatory team","regulatory legal",
        "regulatory compliance legal","competition law","antitrust",
        # M&A and finance legal
        "mergers & acquisitions","m&a","deal team","corporate transactions",
        "legal ops","legal operations","legal technology","legal tech",
        "commercial legal","legal commercial","real estate legal",
        "property legal","planning","planning legal",
    ],

    # ── RISK & COMPLIANCE ─────────────────────────────────────────────────────
    "Risk & Compliance": [
        # Core risk
        "risk","risk management","risk department","risk team",
        "risk division","risk function","risk & compliance",
        "risk and compliance","enterprise risk","enterprise risk management",
        "erm","operational risk","operational risk management","orm",
        "credit risk","market risk","liquidity risk","financial risk management",
        "model risk","technology risk","cyber risk","third party risk",
        "vendor risk","supply chain risk","strategic risk",
        # Compliance
        "compliance","compliance department","compliance team",
        "compliance division","compliance function","regulatory compliance",
        "compliance & risk","compliance and risk","compliance management",
        # GRC
        "grc","governance risk compliance","governance risk and compliance",
        "governance, risk and compliance","governance risk & compliance",
        "governance","governance team","corporate governance",
        "internal controls","controls","controls team","sox",
        "sox compliance","sox controls","j-sox","financial controls",
        # Internal audit
        "internal audit","internal audit department","internal audit team",
        "ia","group internal audit","audit & risk","audit and risk",
        "assurance","internal assurance","risk & assurance",
        "risk and assurance","combined assurance",
        # Financial crime
        "aml","anti money laundering","financial crime","fraud",
        "fraud prevention","fraud risk","fraud & financial crime",
        "kyc","know your customer","sanctions","financial intelligence",
        "counter fraud","economic crime",
        # Regulatory
        "regulatory affairs","regulatory","regulatory risk",
        "conduct risk","compliance monitoring","compliance testing",
        "data protection","dpo office","privacy","ciso",
        "information risk","information governance",
    ],

    # ── CUSTOMER SUPPORT ──────────────────────────────────────────────────────
    "Support": [
        # Core support
        "support","customer support","customer service","client services",
        "client support","customer care","customer relations",
        "customer experience","cx","customer experience team",
        "contact centre","contact center","call centre","call center",
        "customer contact","customer operations","customer ops",
        # Technical support
        "technical support","tech support","helpdesk","help desk",
        "it helpdesk","service desk","it service desk","1st line support",
        "2nd line support","3rd line support","first line","second line",
        "third line","l1","l2","l3","level 1","level 2","level 3",
        # Customer success
        "customer success","cs","customer success team",
        "customer success management","csm","client success",
        "account management support","post-sales",
        # Onboarding
        "onboarding","customer onboarding","client onboarding",
        "implementation","implementations","professional services",
        "ps","customer implementation","solution implementation",
        # After sales
        "after sales","after-sales","aftersales","field service support",
        "warranty","returns","repairs","service centre","service center",
        # Complaints
        "complaints","complaints handling","dispute resolution support",
        "escalations","customer escalations",
    ],

    # ── ENGINEERING & PRODUCT ─────────────────────────────────────────────────
    "Engineering": [
        "engineering","software engineering","software development",
        "development","r&d","research and development","research & development",
        "technology engineering","tech engineering","it engineering",
        "backend","backend engineering","backend development",
        "frontend","frontend engineering","frontend development",
        "full stack","full stack engineering","full stack development",
        "mobile","mobile engineering","mobile development","ios","android",
        "qa engineering","test engineering","quality engineering","sdet",
        "data engineering","data platform engineering",
        "ml engineering","machine learning engineering","ai engineering",
        "platform","platform engineering","infrastructure engineering",
        "devops","devsecops","sre","site reliability engineering",
        "cloud engineering","cloud native","solutions engineering",
        "integration","integration engineering","api","api development",
        "architecture","software architecture","technical architecture",
        "embedded","embedded systems","hardware engineering","firmware",
        "iot","internet of things engineering",
    ],

    "Product": [
        "product","product management","product team","product department",
        "product division","product group","product & engineering",
        "product and engineering","product & design","product and design",
        "product & ux","product & technology","product strategy",
        "product operations","product ops","product development",
        "ux","user experience","ui","user interface","ux/ui","ui/ux",
        "design","design team","product design","experience design",
        "service design","interaction design","visual design",
        "product owner","product owners","business analysis","ba",
        "business analyst","business analysts","requirements",
        "digital product","digital product management",
    ],

    "Data & Analytics": [
        "data","data team","data department","data division",
        "data & analytics","data and analytics","analytics",
        "analytics team","analytics department","business analytics",
        "business intelligence","bi","bi team","reporting",
        "reporting & analytics","data science","data scientists",
        "data engineering","data platform","data infrastructure",
        "data management","data governance","data quality",
        "data strategy","chief data office","cdo office",
        "insights","insights team","customer insights","market insights",
        "consumer insights","research","market research",
        "advanced analytics","predictive analytics","ml","machine learning",
        "ai","artificial intelligence","ai & ml","decision science",
        "decision intelligence","applied science","quantitative",
    ],

    "Executive": [
        "executive","c-suite","c suite","leadership","senior leadership",
        "executive leadership","executive team","exec team","exec",
        "board","board of directors","directors","senior management",
        "management","management team","senior management team","smt",
        "managing directors","executive directors","group executive",
        "ceo office","ceo's office","president","president office",
        "chairman","chairman office","group","group management",
        "corporate","corporate office","headquarters","hq",
        "c-level","c level","office of the ceo","office of the cfo",
        "group leadership","global leadership","global management",
    ],

    # ── ADDITIONAL DEPARTMENTS COMMON IN LARGER ORGANISATIONS ────────────────
    "Customer Success": [
        "customer success","cs department","customer success team",
        "customer success management","client success","account success",
        "partner success","customer growth","customer retention",
        "renewal","renewals","renewal management","expansion",
        "upsell","cross-sell","post-sales success",
    ],

    "Project Management": [
        "project management","pmo","project management office",
        "programme management","program management","portfolio management",
        "project office","project delivery","delivery","delivery management",
        "project team","project managers","programme office",
        "change delivery","transformation delivery","it pmo",
    ],

    "Admin": [
        "admin","administration","administrative","administration department",
        "administrative services","office administration","office management",
        "pa","personal assistant","executive assistant","ea",
        "business support","business support services","admin & support",
        "corporate services","company administration","reception",
        "secretarial","office services","general administration",
    ],

    "Research": [
        "research","r&d","research and development","research & development",
        "innovation","innovation team","innovation lab","lab","laboratories",
        "scientific","science","clinical","clinical research","clinical trials",
        "regulatory affairs research","medical affairs","medical",
        "drug development","product research","market research research",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
#  ACCESS LEVEL SYNONYMS — maps every known variation to canonical form
# ─────────────────────────────────────────────────────────────────────────────
ACCESS_SYNONYMS = {
    "Admin": [
        # Direct admin terms
        "admin","administrator","administration access","system admin",
        "sysadmin","sys admin","system administrator","it admin",
        "local admin","domain admin","global admin","full admin",
        "super admin","superadmin","super administrator",
        "admin access","administrative access","administrative rights",
        "admin rights","admin privileges","administrative privileges",
        # Root / elevated
        "root","root access","superuser","super user","su",
        "elevated","elevated access","elevated privileges",
        "privileged","privileged access","privileged user",
        # Full control
        "fullcontrol","full control","full access","all access",
        "unrestricted","unrestricted access","complete access",
        "all permissions","all rights","everything",
        "owner","resource owner","object owner",
        # Platform specific
        "global administrator","tenant admin","org admin",
        "enterprise admin","azure admin","aws admin",
        "cloud admin","platform admin","infrastructure admin",
        "application admin","app admin","system owner",
    ],

    "DBAdmin": [
        "dbadmin","dba","db admin","database admin","database administrator",
        "database administration","sql admin","sql server admin",
        "oracle dba","oracle admin","postgres admin","postgresql admin",
        "mysql admin","mongodb admin","db owner","database owner",
        "schema owner","schema admin","data admin","data administrator",
        "warehouse admin","datawarehouse admin","db2 admin","sybase admin",
        "nosql admin","redis admin","elasticsearch admin","database access",
    ],

    "Finance": [
        "finance","finance access","financial","financial access",
        "accounts","accounting","accounting access","accounts access",
        "payroll","payroll access","payment","payments","payment access",
        "general ledger","gl","gl access","ap access","ar access",
        "purchase ledger","sales ledger","erp finance","sap","sap finance",
        "sap access","oracle financials","oracle finance","netsuite",
        "sage","xero","quickbooks","dynamics finance","d365",
        "billing","billing access","invoicing","invoice access",
        "collections","treasury access","budgeting access",
    ],

    "HR": [
        "hr","hr access","human resources access","hris","hrms",
        "hris access","hrms access","workday","workday access",
        "oracle hr","sap hr","successfactors","bamboo hr","bamboohr",
        "people system","people access","payroll hr","recruitment access",
        "talent system","ats","applicant tracking","learning system",
        "lms access","performance system","hr portal",
    ],

    "ReadOnly": [
        "readonly","read only","read-only","read","view","view only",
        "view access","read access","viewer","viewers","observer",
        "monitor","monitoring","reporting","report","reports",
        "read & view","read and view","enquiry","enquiry only",
        "query only","query","browse","browse only","lookup",
        "lookup only","basic","basic access","standard read",
        "limited","limited access","restricted","restricted access",
        "no write","no edit","consume","consume only",
        "auditor","auditor access","audit read","compliance read",
    ],

    "Full Access": [
        "full access","full","complete","complete access",
        "unrestricted","all features","all functionality",
        "power user","advanced","advanced access","super user access",
        "manager access","manager level","management access",
        "senior access","full permissions","all permissions",
        "full read write","read write execute","rwx",
        "contributor","contribute","read write","read/write",
    ],

    "CRM": [
        "crm","crm access","salesforce","salesforce access","dynamics crm",
        "dynamics 365","d365 crm","hubspot","hubspot access","zoho crm",
        "customer","customer access","sales access","sales system",
        "account management access","pipeline access","opportunity access",
        "contact management","lead management","crm user","sfdc",
    ],

    "Support": [
        "support","support access","helpdesk","help desk","service desk",
        "itsm","servicenow","jira service","jira sd","zendesk",
        "freshdesk","freshservice","customer support access",
        "ticket","ticketing","ticketing system","incident management",
        "change management access","problem management","cmdb access",
    ],

    "Engineering": [
        "engineering","developer","development","dev","devops",
        "git","github","gitlab","bitbucket","azure devops",
        "code","coding","repository","repo","source control",
        "deploy","deployment","cicd","ci/cd","pipeline",
        "aws","azure","gcp","cloud access","infrastructure access",
        "kubernetes","k8s","docker","container","container access",
        "jira","confluence","atlassian","monitoring access",
        "logging access","observability","release","release management",
    ],

    "Product": [
        "product","product access","product management access",
        "product tool","product analytics","mixpanel","amplitude",
        "pendo","product board","productboard","roadmap",
        "jira product","backlog","sprint","agile tools",
    ],

    "Marketing": [
        "marketing","marketing access","marketing tools","marketing system",
        "cms","content management","content management system",
        "marketing automation","hubspot marketing","marketo","pardot",
        "mailchimp","campaign access","social media tools","hootsuite",
        "google analytics","analytics access","marketing analytics",
        "seo tools","sem tools","advertising access","ad platform",
        "google ads","facebook ads","linkedin ads",
    ],

    "Compliance": [
        "compliance","compliance access","grc","grc access","grc tool",
        "risk","risk access","risk management access","audit access",
        "compliance management","regulatory","regulatory access",
        "policy management","policy access","sox compliance access",
        "archer","servicenow grc","metricstream","compliance portal",
    ],

    "Legal": [
        "legal","legal access","legal tools","contract management access",
        "legal document management","matter management","legal ops",
        "legal operations access","company secretarial access",
        "board portal","sharepoint legal","legal dms","contract lifecycle",
        "clm","contract lifecycle management","e-signature",
        "docusign","adobesign","legal platform",
    ],

    "Operations": [
        "operations","ops access","operations system","operations tool",
        "erp","erp access","supply chain access","logistics access",
        "warehouse management","wms","wms access","inventory access",
        "production access","manufacturing access","mes",
        "field service access","facilities access","fleet access",
        "transport management","tms","procurement access","p2p access",
    ],

    "Procurement": [
        "procurement","procurement access","purchasing access","buying access",
        "sourcing access","supplier portal","vendor portal",
        "p2p","procure to pay access","contract management procurement",
        "coupa","ariba","jaggaer","oracle procurement","sap ariba",
        "spend management","catalogue access","purchase order",
    ],
}

# Build reverse lookups — called once at import, very fast at runtime
_DEPT_LOOKUP = {}
for _canonical, _synonyms in DEPT_SYNONYMS.items():
    _DEPT_LOOKUP[_canonical.lower()] = _canonical
    for _s in _synonyms:
        _DEPT_LOOKUP[_s.lower()] = _canonical

_ACCESS_LOOKUP = {}
for _canonical, _synonyms in ACCESS_SYNONYMS.items():
    _ACCESS_LOOKUP[_canonical.lower()] = _canonical
    for _s in _synonyms:
        _ACCESS_LOOKUP[_s.lower()] = _canonical

IT_DEPT_NAMES = {
    "IT","Information Technology","Technology","Tech","IS","Information Systems",
    "IT Department","IT Services","IT Operations","IT Ops","Infrastructure",
    "Security","IT Security","Cyber","Cyber Security","Cybersecurity",
    "Information Security","InfoSec","DevOps","Dev Ops","Cloud","Platform","SRE",
    "Engineering","Software Engineering","Digital","Network","Systems",
    "Site Reliability","Site Reliability Engineering","Data Engineering",
    "Platform Engineering","Cloud Engineering","Cloud & DevOps",
}

# Override: IT-related departments that should be treated as IT for super-user check
# even if they normalise to "Engineering" or other canonical forms
_IT_OVERRIDE_SYNONYMS = {
    "devops","dev ops","devsecops","sre","site reliability",
    "platform","platform engineering","cloud","cloud engineering",
    "cloud & devops","cloud and devops","infrastructure",
    "network","networking","systems","system administration",
    "it support","it helpdesk","service desk it",
}

def normalise_dept(raw_dept):
    """
    Convert any real-world department name to its canonical form.
    Returns the canonical name if found, otherwise returns the original.

    Examples:
        "Finance & Accounting" → "Finance"
        "Information Technology" → "IT"
        "People & Culture" → "HR"
        "Customer Success" → "Support"
        "Biz Dev" → "Sales"
    """
    if not raw_dept or str(raw_dept).lower() in ("nan","none",""):
        return "Unknown"
    clean = str(raw_dept).strip().lower()
    # Direct lookup
    if clean in _DEPT_LOOKUP:
        return _DEPT_LOOKUP[clean]
    # Partial match — check if any synonym is contained in the dept name
    for synonym, canonical in _DEPT_LOOKUP.items():
        if synonym in clean or clean in synonym:
            return canonical
    # Return original with title case if no match found
    return str(raw_dept).strip()


def normalise_access(raw_access):
    """
    Convert access level variations to canonical form for comparison.
    Handles comma-separated multi-role strings.

    Examples:
        "Full Admin" → "Admin"
        "Database Administrator" → "DBAdmin"
        "Read Only" → "ReadOnly"
        "Finance,HR,Admin" → ["Finance","HR","Admin"]
    """
    if not raw_access or str(raw_access).lower() in ("nan","none",""):
        return []
    # Split on common delimiters
    import re
    parts = re.split(r"[,;|/]", str(raw_access))
    result = []
    for part in parts:
        clean = part.strip().lower()
        if clean in _ACCESS_LOOKUP:
            result.append(_ACCESS_LOOKUP[clean])
        else:
            # Partial match
            matched = False
            for synonym, canonical in _ACCESS_LOOKUP.items():
                if synonym in clean:
                    result.append(canonical)
                    matched = True
                    break
            if not matched:
                result.append(part.strip())
    return list(dict.fromkeys(result))  # deduplicate preserving order


def is_it_department(raw_dept):
    """
    Returns True if the department is an IT-related department.
    Used by the super-user check to avoid false positives.
    Checks canonical name, original name, AND known IT override synonyms.
    """
    if not raw_dept:
        return False
    raw_lower = str(raw_dept).strip().lower()
    canonical = normalise_dept(raw_dept)
    return (
        canonical in IT_DEPT_NAMES or
        canonical.upper() in {d.upper() for d in IT_DEPT_NAMES} or
        raw_lower in _IT_OVERRIDE_SYNONYMS or
        any(s in raw_lower for s in _IT_OVERRIDE_SYNONYMS)
    )



# ─────────────────────────────────────────────────────────────────────────────
#  EMPLOYMENT STATUS NORMALISATION
#  Maps every real-world HR status variation to: Active | Terminated | On Leave
# ─────────────────────────────────────────────────────────────────────────────
TERMINATED_STATUSES = {
    # Standard
    "terminated","resigned","redundant","inactive","dismissed","discharged",
    # Leaver variations
    "leaver","left","ex-employee","ex employee","former employee","former",
    "separated","separation","offboarded","offboard","exited","exit",
    "departed","departed employee","no longer employed","not employed",
    # Contract ended
    "contract ended","contract expired","contract complete","contract finished",
    "end of contract","contract terminated","assignment ended","assignment complete",
    # Other termination types
    "dismissed","dismissal","gross misconduct","misconduct","let go",
    "laid off","layoff","made redundant","voluntary redundancy","compulsory redundancy",
    "early retirement","retired","retirement","deceased","death",
    "withdrawn","closed","ended","ceased","deactivated","disabled","revoked",
    "deleted","removed","archived","historical",
}

ON_LEAVE_STATUSES = {
    # Parental leave
    "maternity","maternity leave","paternity","paternity leave",
    "parental leave","shared parental leave","adoption leave",
    # Other leave
    "sabbatical","garden leave","gardening leave","secondment",
    "furlough","furloughed","loa","leave of absence","on leave",
    "long term sick","long-term sick","sick leave","medical leave",
    "career break","study leave","unpaid leave","extended leave",
    "suspension","suspended","compassionate leave",
}

ACTIVE_STATUSES = {
    "active","employed","current","permanent","full time","full-time",
    "part time","part-time","probation","probationary","working",
    "fixed term","fixed-term","casual","temporary active","new starter",
}

def normalise_status(raw_status):
    """
    Convert any HR employment status to canonical form.
    Returns: 'terminated' | 'on_leave' | 'active'
    """
    if not raw_status or str(raw_status).strip().lower() in ("nan","none",""):
        return "active"  # assume active if blank
    clean = str(raw_status).strip().lower()
    if clean in TERMINATED_STATUSES:
        return "terminated"
    if clean in ON_LEAVE_STATUSES:
        return "on_leave"
    # Partial match for compound statuses
    for term in TERMINATED_STATUSES:
        if term in clean:
            return "terminated"
    for leave in ON_LEAVE_STATUSES:
        if leave in clean:
            return "on_leave"
    return "active"


# ─────────────────────────────────────────────────────────────────────────────
#  CONTRACTOR TYPE NORMALISATION
#  Maps every real-world contractor variation to canonical "contractor"
# ─────────────────────────────────────────────────────────────────────────────
CONTRACTOR_TYPES = {
    "contractor","contract","contracting",
    "agency","agency worker","agency staff","agency employee",
    "interim","interim manager","interim director","interim worker",
    "consultant","consulting","consultancy",
    "freelance","freelancer","freelancing",
    "temporary","temp","temporary worker","temporary staff","temp worker",
    "fixed term","fixed-term","ftc","fixed term contract","fixed-term contract",
    "third party","third-party","3rd party","vendor","outsourced","outsource",
    "contingent","contingent worker","contingent staff",
    "associate","independent","independent contractor",
    "self employed","self-employed","sole trader",
    "zero hours","zero-hours","casual","casual worker","casual staff",
    "gig","gig worker","contract worker","contract staff",
    "statement of work","sow","body shop",
}

def is_contractor(raw_contract_type):
    """
    Returns True if the contract type indicates a non-permanent worker.
    """
    if not raw_contract_type or str(raw_contract_type).strip().lower() in ("nan","none",""):
        return False
    clean = str(raw_contract_type).strip().lower()
    if clean in CONTRACTOR_TYPES:
        return True
    for ct in CONTRACTOR_TYPES:
        if ct in clean:
            return True
    return False

SOD_RULES = {
    "Sales":             ["Admin","Finance","Payroll","DBAdmin","HR"],
    "Marketing":         ["Admin","DBAdmin","Payroll","Finance"],
    "Support":           ["Admin","Finance","DBAdmin","Payroll"],
    "Finance":           ["Admin","DBAdmin"],
    "HR":                ["Admin","DBAdmin","Finance"],
    "Operations":        ["DBAdmin","Finance"],
    "IT":                ["Payroll"],          # IT legitimately manages HR systems — HR removed
    "Procurement":       ["Finance","DBAdmin"],
    "Risk & Compliance": ["Admin","DBAdmin"],
    "Legal":             ["Admin","DBAdmin","Finance"],
}


HIGH_RISK_ACCESS = ["Admin","SuperAdmin","DBAdmin","Root","FullControl","SysAdmin"]

# ─────────────────────────────────────────────────────────────────────────────
#  COMPLIANCE FRAMEWORK REFERENCES
# ─────────────────────────────────────────────────────────────────────────────
FRAMEWORK_REFS = {
    "Orphaned Account":                         {"SOX":"SOX ITGC AC-1 — Terminated user access","ISO_27001":"ISO 27001 A.5.18 — Access rights / A.8.8 Leaver process","GDPR":"GDPR Art.32 — Technical access control measures","PCI_DSS":"PCI-DSS v4.0 Req 8.3.4 — Disable accounts ≤90 days of termination"},
    "Terminated Employee with Active Account":  {"SOX":"SOX ITGC AC-1 — Leaver account not disabled","ISO_27001":"ISO 27001 A.5.18 — Termination of access rights","GDPR":"GDPR Art.32 / Art.5(f) — Integrity and access control","PCI_DSS":"PCI-DSS v4.0 Req 8.3.4 — Disable within 24h of termination"},
    "Post-Termination Login":                   {"SOX":"SOX ITGC AC-1 — Unauthorised post-termination access","ISO_27001":"ISO 27001 A.5.18 / A.8.16 — Monitoring of access","GDPR":"GDPR Art.32 / Art.33 — Possible data breach — notify DPA within 72h","PCI_DSS":"PCI-DSS v4.0 Req 8.3.4 + Req 10.2 — Audit log review"},
    "Dormant Account":                          {"SOX":"SOX ITGC AC-2 — Inactive account not reviewed","ISO_27001":"ISO 27001 A.5.18 — Regular review of access rights","GDPR":"GDPR Art.5(e) — Storage limitation / Art.32 — Access hygiene","PCI_DSS":"PCI-DSS v4.0 Req 8.3.4 — Remove or disable inactive accounts"},
    "Toxic Access (SoD Violation)":             {"SOX":"SOX ITGC AC-3 — Segregation of duties — ICFR deficiency","ISO_27001":"ISO 27001 A.5.3 — Segregation of duties","GDPR":"GDPR Art.32 — Dual control principle","PCI_DSS":"PCI-DSS v4.0 Req 7.1 — Access controls restrict access"},
    "Privilege Creep":                          {"SOX":"SOX ITGC AC-2 — Excess access not revoked on role change","ISO_27001":"ISO 27001 A.5.18 — Least privilege / need-to-know","GDPR":"GDPR Art.25 — Data protection by design","PCI_DSS":"PCI-DSS v4.0 Req 7.2 — Least privilege model"},
    "Shared / Generic Account":                 {"SOX":"SOX ITGC AC-4 — Individual accountability not maintained","ISO_27001":"ISO 27001 A.5.16 — Identity management / accountability","GDPR":"GDPR Art.5(f) — Integrity and confidentiality","PCI_DSS":"PCI-DSS v4.0 Req 8.2.1 — All accounts must be unique"},
    "Service / System Account":                 {"SOX":"SOX ITGC AC-4 — Service account has no named owner","ISO_27001":"ISO 27001 A.5.17 — Authentication info / A.8.2 — Privileged access","GDPR":"GDPR Art.32 — Controls for automated processing","PCI_DSS":"PCI-DSS v4.0 Req 8.6 — Service accounts managed and secured"},
    "Super-User / Admin Access":                {"SOX":"SOX ITGC AC-3 — Privileged access without justification","ISO_27001":"ISO 27001 A.8.2 — Privileged access rights","GDPR":"GDPR Art.25 / Art.32 — Minimise privileged access","PCI_DSS":"PCI-DSS v4.0 Req 7.2.4 — Quarterly review of privileged accounts"},
    "MFA Not Enabled":                          {"SOX":"SOX ITGC AC-5 — Authentication controls — MFA not enforced","ISO_27001":"ISO 27001 A.8.5 — Secure authentication","GDPR":"GDPR Art.32 — Appropriate authentication strength","PCI_DSS":"PCI-DSS v4.0 Req 8.4 — MFA required for all access"},
    "Password Never Expired":                   {"SOX":"SOX ITGC AC-5 — Password policy — credential rotation not enforced","ISO_27001":"ISO 27001 A.5.17 — Authentication information management","GDPR":"GDPR Art.32 — Credential hygiene","PCI_DSS":"PCI-DSS v4.0 Req 8.3.9 — Passwords changed every 90 days"},
    "Duplicate System Access":                  {"SOX":"SOX ITGC AC-4 — Duplicate accounts impair accountability","ISO_27001":"ISO 27001 A.5.16 — Identity management","GDPR":"GDPR Art.5(f) — Data integrity","PCI_DSS":"PCI-DSS v4.0 Req 8.2.1 — All user IDs must be unique"},
    "Excessive Multi-System Access":            {"SOX":"SOX ITGC AC-2 — Access exceeds role requirements","ISO_27001":"ISO 27001 A.5.18 — Least privilege","GDPR":"GDPR Art.25 — Access minimisation","PCI_DSS":"PCI-DSS v4.0 Req 7.2 — Least privilege model"},
    "Near-Match Email":                         {"SOX":"SOX ITGC AC-1 — Identity verification failure","ISO_27001":"ISO 27001 A.5.16 — Identity management","GDPR":"GDPR Art.32 — Accuracy of identity data","PCI_DSS":"PCI-DSS v4.0 Req 8.2 — Proper identification of users"},
    "Contractor Without Expiry Date":           {"SOX":"SOX ITGC AC-2 — Third-party access has no end-date","ISO_27001":"ISO 27001 A.5.19 — Supplier relationship security","GDPR":"GDPR Art.28 — Processor agreements / access time-limits","PCI_DSS":"PCI-DSS v4.0 Req 8.6 — Third-party access must be time-limited"},
    "RBAC Violation":                           {"SOX":"SOX ITGC AC-2 — Access provisioned beyond role entitlement","ISO_27001":"ISO 27001 A.5.15 — Access control / A.5.18 — Role-based access rights","GDPR":"GDPR Art.25 — Data protection by design / least privilege","PCI_DSS":"PCI-DSS v4.0 Req 7.2 — Least privilege access model"},
    "Unauthorised Privileged Account":          {"SOX":"SOX ITGC AC-3 — Privileged access without approval or documentation","ISO_27001":"ISO 27001 A.8.2 — Privileged access rights management","GDPR":"GDPR Art.32 — Appropriate technical controls for privileged access","PCI_DSS":"PCI-DSS v4.0 Req 7.2.4 — Quarterly review of privileged accounts"},
    "Privileged Account Review Overdue":        {"SOX":"SOX ITGC AC-2 — Periodic access review not completed","ISO_27001":"ISO 27001 A.8.2 — Privileged access rights / periodic review","GDPR":"GDPR Art.32 — Ongoing security measures","PCI_DSS":"PCI-DSS v4.0 Req 7.2.4 — Review privileged access quarterly"},
}

# ─────────────────────────────────────────────────────────────────────────────
#  REMEDIATION PLAYBOOK
# ─────────────────────────────────────────────────────────────────────────────
REMEDIATION = {
    "Orphaned Account":                        {"severity":"🔴 CRITICAL","risk":"Active credentials with zero HR record. Any ex-employee, ghost or unknown actor could be using this.","step_1":"Disable account immediately. Do not delete — preserve audit trail.","step_2":"Raise IT ticket. Obtain HR confirmation that no record exists.","step_3":"Review last-login logs for suspicious activity.","step_4":"If unauthorised activity found, escalate to security incident response.","owner":"IT Ops + HR + IT Security","sla":"Disable within 24 hours"},
    "Terminated Employee with Active Account": {"severity":"🔴 CRITICAL","risk":"HR confirms this person has left. Their account should not exist. Clear offboarding failure.","step_1":"Disable account immediately.","step_2":"Review access logs from termination date to today.","step_3":"Confirm whether account was used after termination date.","step_4":"Fix the offboarding process so this cannot recur.","owner":"IT Ops + HR","sla":"Disable within 24 hours"},
    "Post-Termination Login":                  {"severity":"🔴 CRITICAL","risk":"Ex-employee accessed systems after leaving. Potential data breach. Possible GDPR Art.33 notification required.","step_1":"Disable account and preserve all access logs immediately.","step_2":"Escalate to IT Security and Legal. Do not delete any evidence.","step_3":"Determine exactly what data or systems were accessed post-termination.","step_4":"Assess GDPR Art.33 breach notification — 72-hour window from discovery.","owner":"IT Security + Legal + CISO","sla":"Escalate within 1 hour"},
    "Dormant Account":                         {"severity":"🟠 HIGH","risk":"Unused accounts are the most common attacker entry point. No one monitors them for anomalies.","step_1":"Email account owner and line manager requesting justification for continued access.","step_2":"If no response in 5 business days, disable the account.","step_3":"Document the decision and include in next access review cycle.","step_4":"Implement automated dormancy alerting at 60-day threshold.","owner":"Line Manager + IT Ops","sla":"Resolve within 5 business days"},
    "Toxic Access (SoD Violation)":            {"severity":"🔴 CRITICAL","risk":"This user can both initiate and approve transactions. Fraud or error can go completely undetected.","step_1":"Identify which role is excess and remove it immediately.","step_2":"If both roles are genuinely required, implement a compensating control (dual approval).","step_3":"Document any exception with written CISO and Dept Head sign-off.","step_4":"Add to quarterly SoD recertification register.","owner":"IT Security + Dept Head + CISO","sla":"Remediate within 48 hours"},
    "Privilege Creep":                         {"severity":"🟠 HIGH","risk":"Accumulated roles from past transfers or projects. Violates least-privilege. Audit trail is unreliable.","step_1":"Pull the full role history for this user.","step_2":"Send complete access list to current line manager for recertification.","step_3":"Remove all roles not confirmed as business-necessary within 10 days.","step_4":"Implement mandatory role review at every internal transfer going forward.","owner":"Dept Head + IT Ops","sla":"Recertify within 10 business days"},
    "Shared / Generic Account":                {"severity":"🟠 HIGH","risk":"No individual owner. Actions cannot be attributed to a person. Entire audit trail is broken.","step_1":"Identify every individual currently using this account.","step_2":"Provision individual named accounts for each legitimate user.","step_3":"Disable the shared account once individual accounts are confirmed working.","step_4":"Add generic account detection to the provisioning approval workflow.","owner":"IT Ops","sla":"Replace within 30 days"},
    "Service / System Account":                {"severity":"🟡 MEDIUM","risk":"Ownerless service accounts persist indefinitely and silently accumulate excess rights.","step_1":"Identify the application or automated process this account serves.","step_2":"Assign a named human owner with documented accountability.","step_3":"Set a credential rotation schedule — minimum quarterly.","step_4":"Review permissions and reduce to the minimum required for the function.","owner":"IT Ops + Application Owner","sla":"Assign owner within 15 business days"},
    "Super-User / Admin Access":               {"severity":"🟠 HIGH","risk":"Admin rights outside IT is a significant compliance and breach risk. One compromised account = full system access.","step_1":"Request written business justification from the account holder and their manager.","step_2":"If unjustified, downgrade access immediately.","step_3":"Implement Just-In-Time (JIT) admin access to reduce standing privileges.","step_4":"Add to quarterly admin access recertification register.","owner":"CISO + Dept Head","sla":"Justify or revoke within 48 hours"},
    "MFA Not Enabled":                         {"severity":"🟠 HIGH","risk":"One stolen password gives full account access. No second barrier. PCI-DSS and ISO 27001 both mandate MFA.","step_1":"Enforce MFA enrolment for this account immediately.","step_2":"Block login until MFA is configured and verified.","step_3":"Confirm MFA device is corporate-managed, not personal.","step_4":"Add to MFA compliance report for CISO.","owner":"IT Security","sla":"Enrol MFA within 48 hours"},
    "Password Never Expired":                  {"severity":"🟡 MEDIUM","risk":"Stale credentials are the primary vector for credential stuffing and password spray attacks.","step_1":"Force an immediate password reset for this account.","step_2":"Enforce password expiry at the domain or system level.","step_3":"Check this email against known breach databases.","step_4":"Implement MFA as a compensating control if policy enforcement is delayed.","owner":"IT Security","sla":"Force reset within 24 hours"},
    "Duplicate System Access":                 {"severity":"🟡 MEDIUM","risk":"Multiple accounts for one person multiplies the attack surface and makes the audit trail unreliable.","step_1":"Confirm both accounts belong to the same individual.","step_2":"Designate the correct primary account.","step_3":"Disable the duplicate and transfer any necessary access to the primary.","step_4":"Review the provisioning workflow to prevent duplicate creation.","owner":"IT Ops","sla":"Resolve within 5 business days"},
    "Excessive Multi-System Access":           {"severity":"🟡 MEDIUM","risk":"User spans more systems than their current role requires. Almost always legacy access from previous roles.","step_1":"List all systems this user has access to.","step_2":"Send the full list to the line manager for recertification.","step_3":"Remove access to any system not confirmed as business-necessary.","step_4":"Include in next periodic access review cycle.","owner":"Dept Head + IT Ops","sla":"Recertify within 10 business days"},
    "Near-Match Email":                        {"severity":"🟡 MEDIUM","risk":"Email is close but not identical to HR record. Could be a typo, alias, name change, or impersonation attempt.","step_1":"Manually cross-check the system email against HR records.","step_2":"Contact the employee directly to confirm account ownership.","step_3":"If confirmed typo — correct the email in the system.","step_4":"If unrecognised — treat as Orphaned Account and disable immediately.","owner":"HR + IT Ops","sla":"Confirm identity within 3 business days"},
    "Contractor Without Expiry Date":          {"severity":"🟠 HIGH","risk":"Contractor access has no end-date. It will persist indefinitely after the engagement ends. A very common audit gap.","step_1":"Obtain the contract end-date from Procurement or Legal.","step_2":"Set the account expiry date in the system to match.","step_3":"Schedule a reminder review 30 days before expiry.","step_4":"Implement a mandatory contractor access register with renewal process.","owner":"IT Ops + Procurement","sla":"Set expiry within 5 business days"},
}

# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def parse_date(val):
    """Safely parse any date value. Always returns tz-naive datetime or None."""
    if val is None:
        return None
    try:
        if isinstance(val, float) and (pd.isna(val) or val != val):
            return None
        dt = pd.to_datetime(val, errors="coerce")
        if pd.isna(dt):
            return None
        if hasattr(dt, "tzinfo") and dt.tzinfo is not None:
            dt = dt.tz_localize(None)
        return dt
    except Exception:
        return None

def safe_days(dt, today_dt):
    """Days between today and dt. Returns None if dt is None."""
    if dt is None:
        return None
    try:
        d = (today_dt - dt).days
        return int(d)
    except Exception:
        return None

def in_scope(dt, scope_start_dt, scope_end_dt):
    """True if dt falls within scope window."""
    if dt is None:
        return False
    return scope_start_dt <= dt <= scope_end_dt

def sanitise_sheet(name):
    for ch in ["/", "\\", "*", "?", "[", "]", ":"]:
        name = name.replace(ch, "-")
    return name[:31]

def sev_order(sev):
    return {"🔴 CRITICAL": 0, "🟠 HIGH": 1, "🟡 MEDIUM": 2, "⚪ INFO": 3}.get(sev, 9)

def make_finding(row_dict, issue_type, detail, days_inactive=None,
                 post_term_days=None, selected_fw=None):
    rem  = REMEDIATION.get(issue_type, {})
    refs = FRAMEWORK_REFS.get(issue_type, {})

    # ── Guarantee no blank columns on flagged accounts ────────────────────────
    # If FullName is missing, fall back to email prefix (readable identifier)
    email_val   = str(row_dict.get("Email", "")).strip()
    name_val    = str(row_dict.get("FullName", "")).strip()
    if not name_val or name_val.lower() in ("nan","none",""):
        # Derive readable name from email: john.smith@nairs.com → John Smith
        prefix = email_val.split("@")[0] if "@" in email_val else email_val
        name_val = prefix.replace(".", " ").replace("_", " ").title()

    dept_val    = str(row_dict.get("Department", "")).strip()
    if not dept_val or dept_val.lower() in ("nan","none",""):
        dept_val = "Unknown Department"

    access_val  = str(row_dict.get("AccessLevel", "")).strip()
    if not access_val or access_val.lower() in ("nan","none",""):
        access_val = "Not specified"

    job_val     = str(row_dict.get("JobTitle", "")).strip()
    if not job_val or job_val.lower() in ("nan","none",""):
        job_val = "Not specified"

    system_val  = str(row_dict.get("SystemName", "")).strip()
    if not system_val or system_val.lower() in ("nan","none",""):
        system_val = "Not specified"

    f = {
        **row_dict,
        # Override with guaranteed non-blank values
        "Email":            email_val,
        "FullName":         name_val,
        "Department":       dept_val,
        "AccessLevel":      access_val,
        "JobTitle":         job_val,
        "SystemName":       system_val,
        # Finding metadata
        "IssueType":        issue_type,
        "Severity":         rem.get("severity",  "⚪ INFO"),
        "Detail":           detail,
        "Risk":             rem.get("risk",       ""),
        "Step 1 – Action":  rem.get("step_1",     ""),
        "Step 2 – Action":  rem.get("step_2",     ""),
        "Step 3 – Action":  rem.get("step_3",     ""),
        "Step 4 – Action":  rem.get("step_4",     ""),
        "Owner":            rem.get("owner",      ""),
        "SLA":              rem.get("sla",        ""),
        "DaysInactive":     days_inactive,
    }
    if post_term_days is not None:
        f["DaysPostTermination"] = post_term_days
    # Ensure AuditFlag and Notes are always populated — never blank on a flagged row
    if not f.get("AuditFlag") or str(f.get("AuditFlag","")).lower() in ("","nan","none"):
        # Map issue type to audit flag code
        flag_map = {
            "Orphaned Account":                        "ORPHANED",
            "Terminated Employee with Active Account": "TERMINATED_ACTIVE",
            "Post-Termination Login":                  "POST_TERM_LOGIN",
            "Toxic Access (SoD Violation)":            "SOD_VIOLATION",
            "RBAC Violation":                          "RBAC_VIOLATION",
            "Dormant Account":                         "DORMANT",
            "Privilege Creep":                         "PRIVILEGE_CREEP",
            "Shared / Generic Account":                "GENERIC",
            "Super-User / Admin Access":               "SUPERUSER",
            "MFA Not Enabled":                         "MFA_DISABLED",
            "Contractor Without Expiry Date":          "CONTRACTOR_NO_EXPIRY",
            "Service / System Account":                "SERVICE_ACCOUNT",
            "Password Never Expired":                  "PWD_EXPIRED",
            "Duplicate System Access":                 "DUPLICATE",
            "Excessive Multi-System Access":           "EXCESS_SYSTEMS",
            "Near-Match Email":                        "NEAR_MATCH",
            "Unauthorised Privileged Account":         "UNAUTH_PRIV",
            "Privileged Account Review Overdue":       "REGISTRY_OVERDUE",
        }
        f["AuditFlag"] = flag_map.get(issue_type, issue_type.upper().replace(" ","_")[:20])
    if not f.get("Notes") or str(f.get("Notes","")).lower() in ("","nan","none"):
        f["Notes"] = detail[:120] if detail else f"Flagged: {issue_type}"
    # Only include framework refs that were selected
    fw = selected_fw or []
    if "SOX"     in fw: f["SOX Reference"]     = refs.get("SOX",       "")
    if "ISO"     in fw: f["ISO 27001 Ref"]     = refs.get("ISO_27001", "")
    if "GDPR"    in fw: f["GDPR Reference"]    = refs.get("GDPR",      "")
    if "PCI-DSS" in fw: f["PCI-DSS Reference"] = refs.get("PCI_DSS",   "")
    return f

# ─────────────────────────────────────────────────────────────────────────────
#  AUDIT ENGINE — 15 checks, all verified
# ─────────────────────────────────────────────────────────────────────────────
def run_audit(hr_df, sys_df, scope_start, scope_end,
              dormant_days, pwd_expiry_days, fuzzy_threshold,
              max_systems, selected_fw, sod_override=None,
              rbac_matrix=None, registry_df=None):
    # Returns: (findings_df, excluded_count, missing_col_warnings)

    today_dt       = datetime.today()
    scope_start_dt = datetime.combine(scope_start, datetime.min.time())
    scope_end_dt   = datetime.combine(scope_end,   datetime.max.time())
    findings, excluded_count = [], 0
    seen_duplicates  = set()   # tracks emails already flagged for duplicate
    _sod_flagged_emails = set()  # tracks emails flagged for SoD — prevents superuser double-count

    # Apply SoD rules from uploaded SOA/policy document if provided
    # This means findings cite the CLIENT'S own policy, not hardcoded defaults
    active_sod = {**SOD_RULES}
    if sod_override:
        for dept, rules in sod_override.items():
            if dept in active_sod:
                active_sod[dept] = list(set(active_sod[dept] + rules))
            else:
                active_sod[dept] = rules

    # ── Normalise HR ──────────────────────────────────────────────────────────
    hr = hr_df.copy()
    hr["_em"] = hr["Email"].str.strip().str.lower()
    if hr["_em"].duplicated().any():
        dupe_list = hr.loc[hr["_em"].duplicated(keep=False), "Email"].tolist()
        st.warning(f"⚠️ Duplicate emails in HR file — kept first occurrence: {dupe_list[:5]}{'...' if len(dupe_list)>5 else ''}")
        hr = hr.drop_duplicates(subset="_em", keep="first")
    hr_lookup = hr.set_index("_em")
    hr_emails = set(hr["_em"])

    # ── Secondary lookup: EmployeeID → email (handles email format mismatches) ─
    _hr_id_col = next((c for c in hr.columns if c.lower().replace(" ","").replace("_","")
                       in ("employeeid","empid","staffid","workerid","personid","staffno",
                           "employee_number","empno","payrollid")), None)
    _hr_id_lkp = {}   # {employee_id_lower: hr_email}
    if _hr_id_col:
        for _, _r in hr.iterrows():
            _eid = str(_r.get(_hr_id_col,"")).strip().lower()
            if _eid and _eid not in ("nan","none",""):
                _hr_id_lkp[_eid] = str(_r.get("Email","")).strip().lower()

    # ── Secondary lookup: normalised name → email (john.smith → john smith) ───
    _hr_name_lkp = {}  # {normalised_name: hr_email}
    for _, _r in hr.iterrows():
        _nm = str(_r.get("FullName","")).strip().lower()
        if _nm and _nm not in ("nan","none",""):
            _hr_name_lkp[_nm] = str(_r.get("Email","")).strip().lower()

    # ── Normalise System ──────────────────────────────────────────────────────
    sys = sys_df.copy()
    sys["_em"] = sys["Email"].str.strip().str.lower()

    # ── Detect missing columns — build warnings for auditor ───────────────────
    missing_col_warnings = []
    if "LastLoginDate" not in sys.columns or sys["LastLoginDate"].isna().all():
        missing_col_warnings.append(
            "⚠️ LastLoginDate column not found or empty. "
            "Dormant account check could not run. "
            "All accounts should be treated as potentially dormant until login data is provided."
        )
    if "MFA" not in sys.columns or sys["MFA"].isna().all():
        missing_col_warnings.append(
            "⚠️ MFA column not found or empty. "
            "MFA compliance could not be verified for any account. "
            "Request an MFA status report from IT."
        )
    if "PasswordLastSet" not in sys.columns or sys["PasswordLastSet"].isna().all():
        missing_col_warnings.append(
            "⚠️ PasswordLastSet column not found or empty. "
            "Password expiry check could not run. "
            "Request password age report from Active Directory."
        )
    if "SystemName" not in sys.columns or sys["SystemName"].isna().all():
        missing_col_warnings.append(
            "⚠️ SystemName column not found or empty. "
            "Excessive multi-system access check could not run. "
            "Ensure UAL includes the source system for each account."
        )

    # Pre-compute duplicates — PER SYSTEM not per file
    # Real UALs are multi-system: same person in AD + Salesforce + SAP is NORMAL
    # Only flag if same email appears more than once in the SAME SystemName
    # If no SystemName column, fall back to file-level dedup
    import re as _re
    _svc_pat = r"^(svc[._]|svc$|service[._]|batch[._]|noreply|system[._]|backup[._]|admin[._]shared|generic)"
    email_freq = sys["_em"].value_counts()   # kept for display in finding detail

    if "SystemName" in sys.columns and sys["SystemName"].notna().any():
        # Per-system duplicate detection
        # dup_set = emails that appear >1 time within any single system
        _sys_dup = (
            sys.groupby(["SystemName", "_em"])
            .size()
            .reset_index(name="_cnt")
        )
        _sys_dup = _sys_dup[_sys_dup["_cnt"] > 1]
        _svc_re  = _re.compile(_svc_pat, _re.IGNORECASE)
        dup_set  = set(
            em for em in _sys_dup["_em"].unique()
            if not _svc_re.match(str(em))
        )
        # Also track which system each duplicate is in (for finding detail)
        _dup_system = {}
        for _, row in _sys_dup.iterrows():
            _dup_system[row["_em"]] = row["SystemName"]
    else:
        # No SystemName column — fall back to file-level duplicate detection
        dup_set = set(
            em for em, cnt in email_freq.items()
            if cnt > 1 and not _re.match(_svc_pat, str(em), _re.IGNORECASE)
        )
        _dup_system = {}

    # Pre-compute multi-system BEFORE scope filtering
    if "SystemName" in sys.columns:
        sys_freq   = sys.groupby("_em")["SystemName"].nunique()
        excess_set = set(sys_freq[sys_freq > max_systems].index)
    else:
        excess_set = set()

    # ── Row-by-row checks ─────────────────────────────────────────────────────
    for _, row in sys.iterrows():
        u_email  = str(row.get("Email", "")).strip().lower()
        u_access = str(row.get("AccessLevel", "Not specified")).strip()
        # FullName is optional — if absent derive from email prefix
        _raw_name = str(row.get("FullName", "")).strip()
        if _raw_name and _raw_name.lower() not in ("nan","none",""):
            u_name = _raw_name
        else:
            _prefix = u_email.split("@")[0] if "@" in u_email else u_email
            u_name = _prefix.replace(".", " ").replace("_", " ").title()
        u_mfa    = str(row.get("MFA", "")).strip().lower()
        row_dict = row.to_dict()
        # Inject derived name back so make_finding picks it up
        if not row_dict.get("FullName") or str(row_dict.get("FullName","")).lower() in ("nan","none",""):
            row_dict["FullName"] = u_name
        # Collect all issues for this account — one consolidated finding per account
        account_issues = []   # list of (issue_type, detail, days_inactive, post_term_days)

        last_login   = parse_date(row.get("LastLoginDate"))
        pwd_set      = parse_date(row.get("PasswordLastSet"))
        acct_created = parse_date(row.get("AccountCreatedDate"))

        # Use scope_end_dt so dormant/expired = inactive within audit period
        days_idle = safe_days(last_login, scope_end_dt)
        pwd_days  = safe_days(pwd_set,    scope_end_dt)

        # ── SCOPE FILTER ─────────────────────────────────────────────────────
        # Logic:
        #   - No dates at all        → always include (suspicious)
        #   - Any date IN scope      → include
        #   - Account CREATED before scope but logged in DURING scope → include
        #   - Account created before scope, no login in scope → include if
        #     AccountCreatedDate predates scope (could be dormant — important finding)
        #   - All dates AFTER scope end → exclude (future data, wrong file)
        # This ensures forensic/historical audits catch all relevant accounts.
        has_any_date = any([last_login, pwd_set, acct_created])

        # Include if any date falls within scope
        date_in_scope = (
            in_scope(last_login,   scope_start_dt, scope_end_dt) or
            in_scope(pwd_set,      scope_start_dt, scope_end_dt) or
            in_scope(acct_created, scope_start_dt, scope_end_dt)
        )

        # Also include if account was CREATED before scope end
        # (active accounts that predate the audit period are valid subjects)
        account_predates_scope_end = (
            acct_created is not None and acct_created <= scope_end_dt
        )

        # Also include if last login was before scope end
        # (account was active up to or during the audit period)
        active_before_scope_end = (
            last_login is not None and last_login <= scope_end_dt
        )

        should_include = (
            not has_any_date or          # no dates = always include
            date_in_scope or             # any date in scope window
            account_predates_scope_end or # account existed before scope end
            active_before_scope_end       # account was used before scope end
        )

        # Exclude only if ALL dates are clearly AFTER the scope end
        # (this catches wrong-year data uploads)
        all_dates_after_scope = has_any_date and all([
            (last_login   is None or last_login   > scope_end_dt),
            (pwd_set      is None or pwd_set      > scope_end_dt),
            (acct_created is None or acct_created > scope_end_dt),
        ])

        if all_dates_after_scope:
            excluded_count += 1
            continue

        # ── Generic/service detection — email PREFIX only, never the domain ──────
        # prefix = "john.smith" from "john.smith@company.com"
        # This prevents @testco.com, @systemsco.com, @adminsoftware.com from matching
        email_prefix = u_email.split("@")[0].lower()

        # Service account: starts with svc/batch/backup etc OR is exactly one of these
        _SVC_STARTS = ("svc.","svc_","svc-","service.","service_","batch.","batch_",
                       "backup.","noreply.","noreply","no-reply","app.","system.","system_")
        _SVC_EXACT  = {"svc","batch","backup","root","system","service","noreply"}
        is_svc = (email_prefix in _SVC_EXACT or
                  any(email_prefix.startswith(p) for p in _SVC_STARTS))

        # Generic account: shared/helpdesk/admin/test@ style accounts
        # "test" only matches if the ENTIRE prefix is "test" or starts with "test."
        # NOT if "test" appears somewhere in the middle like "latest" or "protest"
        _GEN_EXACT  = {"test","admin","helpdesk","shared","generic","temp","default",
                       "guest","info","support","administrator","administration",
                       "postmaster","abuse","spam","webmaster","no-reply","mailer-daemon",
                       "it","security","network","devops","cloud","system","service"}
        _GEN_STARTS = ("test.","test_","test-","admin.","admin_","admin-",
                       "helpdesk.","shared.","shared_","generic.","temp.",
                       "default.","guest.","info@","support.")
        is_generic = (email_prefix in _GEN_EXACT or
                      any(email_prefix.startswith(p) for p in _GEN_STARTS))

        # ═══════════════════════════════════════════════════════════════════
        # CHECK 1 & 2: Generic / Service accounts
        # Checked FIRST — these never have HR records and that's expected
        # ═══════════════════════════════════════════════════════════════════
        if is_svc or is_generic:
            itype = "Service / System Account" if is_svc else "Shared / Generic Account"
            findings.append(make_finding(
                row_dict, itype,
                f"'{u_name}' matches {'service/system' if is_svc else 'shared/generic'} "
                f"account patterns. No individual owner — audit trail is broken.",
                days_idle, selected_fw=selected_fw,
            ))
            continue   # skip HR checks — generic accounts won't be in HR

        # ═══════════════════════════════════════════════════════════════════
        # CHECK 3: Orphaned account / Near-match email
        # ═══════════════════════════════════════════════════════════════════
        if u_email not in hr_emails:
            # ── Try secondary matching before flagging as orphaned ─────────────
            _resolved = None

            # Try 1: EmployeeID match — most reliable when email formats differ
            _eid_col = next((c for c in row.index if str(c).lower().replace(" ","").replace("_","")
                             in ("employeeid","empid","staffid","workerid","personid",
                                 "staffno","employeenumber","empno","payrollid")), None)
            if _eid_col:
                _eid_val = str(row.get(_eid_col,"")).strip().lower()
                if _eid_val and _eid_val not in ("nan","none","") and _eid_val in _hr_id_lkp:
                    _resolved = _hr_id_lkp[_eid_val]

            # Try 2: Name derived from email prefix → match HR FullName
            # Handles: j.smith → John Smith, jsmith → John Smith, john.s → John Smith
            if not _resolved:
                _prefix = u_email.split("@")[0].lower()
                _parts  = _prefix.replace("_",".").replace("-",".").split(".")
                for _hr_name, _hr_email in _hr_name_lkp.items():
                    _np = _hr_name.split()
                    if len(_np) >= 2:
                        _fn, _ln = _np[0].lower(), _np[-1].lower()
                        # Handle dotted prefixes: john.smith, j.smith, john.s
                        _dot_match = (len(_parts) >= 2 and (
                            (_parts[0]==_fn and _parts[-1]==_ln) or
                            (len(_parts[0])==1 and _parts[0]==_fn[0] and _parts[-1]==_ln) or
                            (_parts[0]==_fn and len(_parts[-1])==1 and _parts[-1]==_ln[0])
                        ))
                        # Handle no-dot prefixes: jsmith, johnsmith, jsmith
                        _nodot_match = (
                            _prefix == f"{_fn[0]}{_ln}" or      # jsmith
                            _prefix == f"{_fn}{_ln[0]}" or      # johns
                            _prefix == f"{_fn}{_ln}"             # johnsmith
                        )
                        if _dot_match or _nodot_match:
                            _resolved = _hr_email
                            break

            if _resolved and _resolved in hr_emails:
                # Matched via EmployeeID or name — treat as known employee
                u_email = _resolved
                row_dict["Email"] = _resolved
                # Fall through to HR checks below — do NOT flag as orphaned
            else:
                # Truly not in HR — try near-match then orphaned
                # Cap to first 5000 HR emails for performance on large populations
                best_score, best_match = 0, None
                _hr_sample = list(hr_emails)[:5000]
                for he in _hr_sample:
                    s = fuzz.ratio(u_email, he)
                    if s > best_score:
                        best_score, best_match = s, he

                if best_score >= fuzzy_threshold:
                    findings.append(make_finding(
                        row_dict, "Near-Match Email",
                        f"'{u_email}' is {best_score}% similar to HR email '{best_match}'. "
                        f"Possible typo, alias or name change — verify before raising as orphan.",
                        days_idle, selected_fw=selected_fw,
                    ))
                else:
                    findings.append(make_finding(
                        row_dict, "Orphaned Account",
                        f"No HR record found. Not matched by email, EmployeeID or name. "
                        f"Likely a leaver, ex-contractor or ghost account with active access.",
                        days_idle, selected_fw=selected_fw,
                    ))
                continue   # no HR record = skip all deeper checks        # ─── Account IS in HR — run all deeper checks ─────────────────────
        hr_row     = hr_lookup.loc[u_email]
        _raw_dept  = str(hr_row.get("Department", "Unknown")).strip()
        dept       = normalise_dept(_raw_dept)   # "Finance & Accounting" → "Finance"
        _raw_status  = str(hr_row.get("EmploymentStatus", "Active")).strip()
        emp_status   = normalise_status(_raw_status)   # "Leaver" → "terminated" etc.
        _raw_contract = str(hr_row.get("ContractType","")).strip()
        contract      = _raw_contract.strip().lower()   # kept for backwards compat
        term_date  = parse_date(hr_row.get("TerminationDate"))

        # ═══════════════════════════════════════════════════════════════════
        # CHECK 4 & 5: Terminated employee / Post-termination login
        # ═══════════════════════════════════════════════════════════════════
        if emp_status == "terminated":  # normalise_status handles all variations
            if last_login and term_date and last_login.date() > term_date.date():
                post_days = (last_login.date() - term_date.date()).days
                findings.append(make_finding(
                    row_dict, "Post-Termination Login",
                    f"'{u_name}' (status: {emp_status}) logged in {post_days} day(s) "
                    f"AFTER termination date {term_date.date()}. "
                    f"Last login: {last_login.date()}. Treat as potential data breach.",
                    days_idle, post_term_days=post_days, selected_fw=selected_fw,
                ))
            else:
                findings.append(make_finding(
                    row_dict, "Terminated Employee with Active Account",
                    f"HR status is '{emp_status}'"
                    f"{' (terminated ' + str(term_date.date()) + ')' if term_date else ''}"
                    f" but system account is still enabled.",
                    days_idle, selected_fw=selected_fw,
                ))
            continue   # terminated = skip remaining checks

        # ═══════════════════════════════════════════════════════════════════
        # CHECK 6: Contractor without expiry date
        # ═══════════════════════════════════════════════════════════════════
        _join_raw = hr_row.get("JoinDate") or hr_row.get("StartDate") or hr_row.get("HireDate")
        _join_dt  = parse_date(_join_raw)
        _days_join = safe_days(_join_dt, scope_end_dt) if _join_dt else 9999
        if (is_contractor(_raw_contract) and term_date is None
                and (_days_join is None or _days_join > 30)):
            account_issues.append((
                "Contractor Without Expiry Date",
                f"Contractor with no expiry date ({int(_days_join) if _days_join else 'unknown'} days in system). Access will persist indefinitely.",
                days_idle, None
            ))
        # Note: does NOT continue — contractor can also be dormant, SoD-violating etc.

        # ═══════════════════════════════════════════════════════════════════
        # CHECK 7: Dormant account
        # ═══════════════════════════════════════════════════════════════════
        if days_idle is not None and days_idle > dormant_days:
            account_issues.append((
                "Dormant Account",
                f"No login for {days_idle} days (threshold: {dormant_days} days). Last login: {last_login.date() if last_login else 'never recorded'}.",
                days_idle, None
            ))

        # ═══════════════════════════════════════════════════════════════════
        # CHECK 8: MFA not enabled
        # Only fires if MFA column exists AND value clearly means disabled
        # ═══════════════════════════════════════════════════════════════════
        if "MFA" in sys.columns:
            mfa_disabled = u_mfa in ("disabled", "no", "false", "0", "none", "not enrolled")
            if mfa_disabled:
                account_issues.append((
                    "MFA Not Enabled",
                    f"MFA recorded as '{row.get('MFA', '')}'. Single compromised password = full account access.",
                    days_idle, None
                ))

        # ═══════════════════════════════════════════════════════════════════
        # CHECK 9: SoD violation
        # Uses dept from HR (more reliable than system file dept column)
        # ═══════════════════════════════════════════════════════════════════
        forbidden = active_sod.get(dept, [])
        # Also check normalised canonical department name
        if not forbidden:
            forbidden = active_sod.get(normalise_dept(dept), [])
        _norm_access = normalise_access(u_access)  # ["Finance","Admin"] etc.
        # Collect ALL forbidden access levels this account holds — report in one finding
        _violations = []
        for fb in forbidden:
            _fb_norm = normalise_access(fb)
            _fb_canonical = _fb_norm[0] if _fb_norm else fb
            # Use normalised access list comparison only — avoids substring false positives
            # e.g. "Finance" must not match "FinanceAdmin" or "UnauthorisedFinance"
            if (_fb_canonical in _norm_access or
                    any(_fb_canonical.lower() == a.lower() for a in _norm_access) or
                    any(fb.lower() == a.lower() for a in _norm_access)):
                _violations.append(fb)
        if _violations:
            _viol_str = ", ".join(_violations)
            account_issues.append((
                "Toxic Access (SoD Violation)",
                f"Forbidden access '{_viol_str}' for '{dept}' dept. User can initiate and approve without oversight.",
                days_idle, None
            ))
            _sod_flagged_emails.add(u_email)

        # ═══════════════════════════════════════════════════════════════════
        # CHECK 10: Privilege creep (4+ roles)
        # ═══════════════════════════════════════════════════════════════════
        roles = [r.strip() for r in u_access.split(",") if r.strip()]
        if len(roles) >= 4:
            account_issues.append((
                "Privilege Creep",
                f"Holds {len(roles)} roles: {u_access}. Excess access accumulated from previous positions — violates least-privilege.",
                days_idle, None
            ))

        # ═══════════════════════════════════════════════════════════════════
        # CHECK 11: Super-user outside IT
        # Only fires if not already flagged by SoD check for same access level.
        # This prevents double-counting where SoD and superuser both fire.
        # ═══════════════════════════════════════════════════════════════════
        is_it_dept = is_it_department(dept)  # intelligent IT dept detection
        # Check if this account was already flagged for SoD — use full findings list
        # Track via a set for O(1) lookup instead of scanning the list
        _already_sod = u_email in _sod_flagged_emails
        if not _already_sod:
            for hr_kw in HIGH_RISK_ACCESS:
                if hr_kw.lower() in u_access.lower() and not is_it_dept:
                    account_issues.append((
                        "Super-User / Admin Access",
                        f"'{dept}' user holds '{u_access}'. Admin rights for non-IT user requires CISO approval and registry entry.",
                        days_idle, None
                    ))
                    break

        # ═══════════════════════════════════════════════════════════════════
        # CHECK 12: Password never expired
        # ═══════════════════════════════════════════════════════════════════
        if pwd_days is not None and pwd_days > pwd_expiry_days:
            account_issues.append((
                "Password Never Expired",
                f"Password last set {pwd_days} days ago ({pwd_set.date() if pwd_set else 'unknown'}). Policy requires rotation every {pwd_expiry_days} days.",
                days_idle, None
            ))

        # ═══════════════════════════════════════════════════════════════════
        # CHECK 13: Duplicate system account
        # Only flag the SECOND+ occurrence — first occurrence is the primary account
        # ═══════════════════════════════════════════════════════════════════
        if u_email in dup_set:
            if u_email in seen_duplicates:
                # This is the extra occurrence — flag it
                _dup_sys_name = _dup_system.get(u_email, "same system")
                _dup_count = int(email_freq.get(u_email, 2))
                account_issues.append((
                    "Duplicate System Access",
                    f"Email appears more than once in '{_dup_sys_name}'. "
                    f"Multiple active account IDs for one person in the same system — only one account permitted.",
                    days_idle, None
                ))
            else:
                # First occurrence — mark as seen, do not flag
                seen_duplicates.add(u_email)

        # ═══════════════════════════════════════════════════════════════════
        # CHECK 14: Excessive multi-system access
        # ═══════════════════════════════════════════════════════════════════
        if u_email in excess_set:
            n = int(sys_freq[u_email])
            account_issues.append((
                "Excessive Multi-System Access",
                f"Access to {n} systems (threshold: {max_systems}). Likely legacy access from previous roles.",
                days_idle, None
            ))


        # ── CONSOLIDATE all issues for this account into ONE finding ──────────
        if account_issues:
            # Determine highest severity
            SEV_ORDER = {"🔴 CRITICAL": 0, "🟠 HIGH": 1, "🟡 MEDIUM": 2, "⚪ INFO": 3}
            issue_types   = [i[0] for i in account_issues]
            issue_details = [i[1] for i in account_issues]
            issue_idle    = next((i[2] for i in account_issues if i[2] is not None), days_idle)

            # Get severities from REMEDIATION dict
            severities = [REMEDIATION.get(t, {}).get("severity", "🟡 MEDIUM") for t in issue_types]
            top_sev    = min(severities, key=lambda s: SEV_ORDER.get(s, 3))

            if len(issue_types) == 1:
                # Single issue — use normal make_finding
                primary_type   = issue_types[0]
                primary_detail = issue_details[0]
            else:
                # Multiple issues — consolidate
                primary_type   = issue_types[0]   # lead with highest severity issue
                issues_list    = " | ".join([f"{t}: {d}" for t, d in zip(issue_types, issue_details)])
                primary_detail = f"MULTIPLE ISSUES ({len(issue_types)}): {issues_list}"

            f = make_finding(
                row_dict, primary_type, primary_detail,
                issue_idle, selected_fw=selected_fw,
            )
            # Override severity to highest found across all issues
            f["Severity"]    = top_sev
            # Add all issue types as a pipe-separated string for filtering
            f["AllIssues"]   = " | ".join(issue_types)
            f["IssueCount"]  = len(issue_types)
            findings.append(f)

    # ── RBAC Matrix checks ───────────────────────────────────────────────────
    if rbac_matrix:
        rbac_findings = run_rbac_checks(sys_df, hr_df, rbac_matrix, selected_fw, today_dt)
        findings.extend(rbac_findings)

    # ── Privileged User Registry checks ──────────────────────────────────────
    if registry_df is not None:
        reg_findings = run_registry_checks(sys_df, hr_df, registry_df, selected_fw, today_dt)
        findings.extend(reg_findings)

    # ── Build findings DataFrame ──────────────────────────────────────────────
    if not findings:
        return pd.DataFrame(), excluded_count, missing_col_warnings

    df = pd.DataFrame(findings)
    df.insert(0, "ScopeTo",   str(scope_end))
    df.insert(0, "ScopeFrom", str(scope_start))
    df["_ord"] = df["Severity"].map(sev_order).fillna(9)
    df = df.sort_values("_ord").drop(columns="_ord")
    return df, excluded_count, missing_col_warnings

# ─────────────────────────────────────────────────────────────────────────────
#  AUDIT OPINION GENERATOR
# ─────────────────────────────────────────────────────────────────────────────
def generate_opinion(findings_df, meta, scope_start, scope_end, total_pop, in_scope_count):
    total    = len(findings_df)
    critical = len(findings_df[findings_df["Severity"] == "🔴 CRITICAL"]) if total else 0
    high     = len(findings_df[findings_df["Severity"] == "🟠 HIGH"])     if total else 0
    medium   = len(findings_df[findings_df["Severity"] == "🟡 MEDIUM"])   if total else 0

    if critical >= 5:
        level = "ADVERSE"
        body  = ("Based on the results of our identity and access review, we are of the opinion that "
                 "the access control environment contains significant deficiencies constituting a "
                 "material weakness in the organisation's IT General Controls (ITGCs). The volume and "
                 "severity of findings indicate logical access controls are not operating effectively.")
    elif critical >= 1 or high >= 5:
        level = "QUALIFIED"
        body  = ("Based on the results of our identity and access review, we are of the opinion that, "
                 "except for the matters detailed in the findings schedule, the access control environment "
                 "is broadly consistent with good practice. The critical and high-severity findings "
                 "represent control deficiencies requiring prompt remediation.")
    elif high >= 1 or medium >= 3:
        level = "EMPHASIS OF MATTER"
        body  = ("Based on the results of our identity and access review, we are of the opinion that "
                 "the access control environment is generally adequate. We draw attention to the findings "
                 "below which require improvement but do not constitute a material weakness.")
    else:
        level = "UNQUALIFIED (CLEAN)"
        body  = ("Based on the results of our identity and access review, we are of the opinion that "
                 "the access control environment is operating effectively in accordance with the "
                 "organisation's stated policies. No material issues were identified.")

    return (
        f"AUDIT OPINION — IDENTITY & ACCESS CONTROL REVIEW\n"
        f"{'='*60}\n"
        f"Engagement Reference : {meta.get('ref','N/A')}\n"
        f"Client Organisation  : {meta.get('client','N/A')}\n"
        f"Lead Auditor         : {meta.get('auditor','N/A')}\n"
        f"Audit Standard       : {meta.get('standard','N/A')}\n"
        f"Review Period        : {scope_start.strftime('%d %B %Y')} to {scope_end.strftime('%d %B %Y')}\n"
        f"Population           : {total_pop:,} total | {in_scope_count:,} in scope\n"
        f"Date of Opinion      : {datetime.today().strftime('%d %B %Y')}\n\n"
        f"OPINION: {level}\n"
        f"{'-'*60}\n"
        f"{body}\n\n"
        f"FINDINGS SUMMARY\n"
        f"{'-'*60}\n"
        f"Total findings : {total}\n"
        f"  Critical     : {critical}\n"
        f"  High         : {high}\n"
        f"  Medium       : {medium}\n\n"
        f"This opinion is based solely on data provided at the date of review and must be\n"
        f"read with the full findings schedule. Prepared by: {meta.get('auditor','N/A')}"
    )

# ─────────────────────────────────────────────────────────────────────────────
#  EXCEL EXPORT — workpaper grade
# ─────────────────────────────────────────────────────────────────────────────
def to_excel_bytes(findings_df, hr_df, sys_df, scope_start, scope_end,
                   excluded_count, meta, opinion_text):
    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine="xlsxwriter") as writer:
        wb = writer.book

        H  = wb.add_format({"bold":True,"bg_color":"#1F3864","font_color":"white","border":1,"font_name":"Arial","font_size":10})
        R  = wb.add_format({"bg_color":"#FFDEDE","font_name":"Arial","font_size":9})
        O  = wb.add_format({"bg_color":"#FFF0CC","font_name":"Arial","font_size":9})
        Y  = wb.add_format({"bg_color":"#FFFBCC","font_name":"Arial","font_size":9})
        TL = wb.add_format({"bold":True,"font_name":"Arial","font_size":10,"font_color":"#1F3864"})
        TV = wb.add_format({"font_name":"Arial","font_size":10})
        TT = wb.add_format({"bold":True,"font_name":"Arial","font_size":14,"font_color":"#1F3864"})
        OP = wb.add_format({"font_name":"Arial","font_size":10,"text_wrap":True,"valign":"top"})

        def write_sheet(df, name):
            if df is None or df.empty:
                return
            clean = df[[c for c in df.columns if not c.startswith("_")]].copy()
            clean.to_excel(writer, index=False, sheet_name=name)
            ws = writer.sheets[name]
            for ci, col in enumerate(clean.columns):
                try:
                    mx = int(clean[col].fillna("").astype(str).map(len).max())
                except Exception:
                    mx = 10
                ws.set_column(ci, ci, min(max(mx, len(col)) + 2, 60))
            for ri, (_, row) in enumerate(clean.iterrows(), start=1):
                s = str(row.get("Severity", ""))
                fmt = R if "CRITICAL" in s else (O if "HIGH" in s else (Y if "MEDIUM" in s else None))
                if fmt:
                    ws.set_row(ri, None, fmt)
            for ci, col in enumerate(clean.columns):
                ws.write(0, ci, col, H)

        # Sheet 1 — Engagement Cover
        wc = wb.add_worksheet("Engagement Cover")
        wc.hide_gridlines(2)
        wc.set_column("A:A", 4); wc.set_column("B:B", 34); wc.set_column("C:C", 52)
        wc.set_row(1, 8); wc.write("B2", "Identity & Access Control Audit Report", TT)
        wc.set_row(2, 6)
        in_scope_n = len(sys_df) - excluded_count
        cover_rows = [
            ("Client Organisation",   meta.get("client",   "—")),
            ("Engagement Reference",  meta.get("ref",      "—")),
            ("Audit Standard",        meta.get("standard", "—")),
            ("Lead Auditor",          meta.get("auditor",  "—")),
            ("Review Period",         f"{scope_start.strftime('%d %b %Y')} → {scope_end.strftime('%d %b %Y')}"),
            ("Date of Report",        datetime.today().strftime("%d %B %Y")),
            ("Total Population",      f"{len(sys_df):,} system accounts"),
            ("Accounts in Scope",     f"{in_scope_n:,} accounts"),
            ("Excluded (out of scope)",f"{excluded_count:,} accounts"),
            ("Total Findings",        str(len(findings_df))),
            ("Critical Findings",     str(len(findings_df[findings_df["Severity"]=="🔴 CRITICAL"])) if not findings_df.empty else "0"),
            ("Classification",        "CONFIDENTIAL — Internal audit use only"),
        ]
        for i, (lbl, val) in enumerate(cover_rows, start=3):
            wc.set_row(i, 18)
            wc.write(i, 1, lbl, TL); wc.write(i, 2, val, TV)

        # Sheet 2 — Audit Opinion
        wo = wb.add_worksheet("Audit Opinion")
        wo.hide_gridlines(2); wo.set_column("A:A", 4); wo.set_column("B:B", 100)
        wo.set_row(1, 8)
        wo.write("B2", "Audit Opinion — Identity & Access Control Review", TT)
        wo.set_row(2, 6)
        for i, line in enumerate(opinion_text.split("\n"), start=3):
            wo.set_row(i, 15); wo.write(i, 1, line, OP)

        # Sheet 3 — Executive Summary
        in_scope_c = len(sys_df) - excluded_count
        def ci(t): return len(findings_df[findings_df["IssueType"]==t]) if not findings_df.empty else 0
        def cs(s): return len(findings_df[findings_df["Severity"]==s])  if not findings_df.empty else 0
        summary = pd.DataFrame([
            ("── ENGAGEMENT ──",                    ""),
            ("Client",                              meta.get("client","—")),
            ("Reference",                           meta.get("ref","—")),
            ("Auditor",                             meta.get("auditor","—")),
            ("Standard",                            meta.get("standard","—")),
            ("Scope from",                          scope_start.strftime("%d %b %Y")),
            ("Scope to",                            scope_end.strftime("%d %b %Y")),
            ("── POPULATION ──",                    ""),
            ("Total system accounts",               len(sys_df)),
            ("Accounts within scope",               in_scope_c),
            ("Accounts excluded",                   excluded_count),
            ("── FINDINGS ──",                      ""),
            ("Total findings",                      len(findings_df)),
            ("Critical",                            cs("🔴 CRITICAL")),
            ("High",                                cs("🟠 HIGH")),
            ("Medium",                              cs("🟡 MEDIUM")),
            ("── BY CHECK ──",                      ""),
            ("Orphaned accounts",                   ci("Orphaned Account")),
            ("Terminated with active access",       ci("Terminated Employee with Active Account")),
            ("Post-termination logins",             ci("Post-Termination Login")),
            ("Dormant accounts",                    ci("Dormant Account")),
            ("SoD violations",                      ci("Toxic Access (SoD Violation)")),
            ("Privilege creep",                     ci("Privilege Creep")),
            ("Shared / generic accounts",           ci("Shared / Generic Account")),
            ("Service accounts without owner",      ci("Service / System Account")),
            ("Super-user outside IT",               ci("Super-User / Admin Access")),
            ("MFA not enabled",                     ci("MFA Not Enabled")),
            ("Passwords never expired",             ci("Password Never Expired")),
            ("Duplicate system accounts",           ci("Duplicate System Access")),
            ("Excessive multi-system access",       ci("Excessive Multi-System Access")),
            ("Contractors without expiry",          ci("Contractor Without Expiry Date")),
            ("Near-match emails",                   ci("Near-Match Email")),
        ], columns=["Check", "Count"])
        summary.to_excel(writer, index=False, sheet_name="Executive Summary")
        ws_s = writer.sheets["Executive Summary"]
        ws_s.set_column(0, 0, 46); ws_s.set_column(1, 1, 12)
        ws_s.write(0, 0, "Check", H); ws_s.write(0, 1, "Count", H)

        # Sheet 4 — All Findings
        write_sheet(findings_df, "All Findings")

        # Sheet 5 — Remediation Playbook
        pb_cols = ["Severity","IssueType","ScopeFrom","ScopeTo","Email","FullName",
                   "Department","AccessLevel","Detail",
                   "Step 1 – Action","Step 2 – Action","Step 3 – Action","Step 4 – Action",
                   "Owner","SLA","DaysInactive","DaysPostTermination",
                   "SOX Reference","ISO 27001 Ref","GDPR Reference","PCI-DSS Reference"]
        pb = findings_df[[c for c in pb_cols if c in findings_df.columns]] if not findings_df.empty else pd.DataFrame()
        write_sheet(pb, "Remediation Playbook")

        # Per-issue-type sheets
        if not findings_df.empty:
            for itype in findings_df["IssueType"].unique():
                write_sheet(findings_df[findings_df["IssueType"] == itype], sanitise_sheet(itype))

        # Audit Sample sheet
        sample_export = generate_audit_sample(findings_df, 25)
        add_sample_sheet(writer, sample_export, wb, H, R, O, Y)

        # Raw data
        hr_clean  = hr_df.drop(columns=["_em","_email"], errors="ignore")
        sys_clean = sys_df.drop(columns=["_em","_email"], errors="ignore")
        hr_clean.to_excel(writer,  index=False, sheet_name="HR Master (Raw)")
        sys_clean.to_excel(writer, index=False, sheet_name="System Access (Raw)")
        for sn, src in [("HR Master (Raw)", hr_clean), ("System Access (Raw)", sys_clean)]:
            ws_r = writer.sheets[sn]
            for ci2, col in enumerate(src.columns):
                ws_r.write(0, ci2, col, H)

    buf.seek(0)
    return buf.getvalue()



# ─────────────────────────────────────────────────────────────────────────────
#  FEATURE 1: CLAUDE VISION OCR — extract system access data from images/PDFs
# ─────────────────────────────────────────────────────────────────────────────
def ocr_via_ai(uploaded_file):
    """
    Send an image or PDF screenshot to the AI for data extraction.
    Returns a DataFrame matching the system access schema, or None on failure.
    """
    import requests
    try:
        file_bytes = uploaded_file.read()
        b64        = base64.b64encode(file_bytes).decode("utf-8")
        fname      = uploaded_file.name.lower()
        media_type = "application/pdf" if fname.endswith(".pdf") else "image/png" if fname.endswith(".png") else "image/jpeg"

        prompt = """You are an IT audit assistant. The image shows a legacy system access report 
(could be a green-screen terminal, a PDF printout, or a screenshot).

Extract ALL user account rows you can see and return them as a JSON array.
Each object must have these exact keys (use null if not visible):
  Email, FullName, Department, AccessLevel, LastLoginDate, PasswordLastSet,
  AccountCreatedDate, MFA, SystemName, AccountStatus

Rules:
- Email: if no email shown, construct one from username as username@unknown.local
- AccessLevel: map role names to: Admin, DBAdmin, Finance, HR, CRM, Payroll, ReadOnly, Support
- Dates: format as YYYY-MM-DD
- MFA: Enabled or Disabled
- AccountStatus: Enabled or Disabled

Return ONLY the JSON array, no other text, no markdown fences."""

        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"Content-Type": "application/json"},
            json={
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 2000,
                "messages": [{
                    "role": "user",
                    "content": [
                        {"type": "image", "source": {"type": "base64", "media_type": media_type, "data": b64}},
                        {"type": "text",  "text": prompt}
                    ]
                }]
            }
        )
        if response.status_code != 200:
            return None, f"API error {response.status_code}: {response.text[:200]}"

        text = response.json()["content"][0]["text"].strip()
        text = re.sub(r"^```json|^```|```$", "", text.strip(), flags=re.MULTILINE).strip()
        rows = json.loads(text)
        df   = pd.DataFrame(rows)
        return df, None

    except json.JSONDecodeError as e:
        return None, f"Could not parse AI response as JSON: {e}"
    except Exception as e:
        return None, f"OCR failed: {e}"


# ─────────────────────────────────────────────────────────────────────────────
#  FEATURE 2: DYNAMIC SoD MATRIX — read from uploaded Excel
# ─────────────────────────────────────────────────────────────────────────────
def load_sod_matrix(uploaded_file):
    """
    Read a standalone SoD Matrix Excel file.
    Expects columns: Department, ForbiddenAccessLevels (comma-separated)
    Also accepts our SOA format which has a 'SoD Rules' sheet.
    Returns dict {dept: [forbidden_levels]} or empty dict.
    """
    try:
        uploaded_file.seek(0)
        xl = pd.ExcelFile(uploaded_file)
        sheet = None

        # Try to find the right sheet
        for name in xl.sheet_names:
            if any(k in name.lower() for k in ["sod", "segregation", "matrix", "rules"]):
                sheet = name
                break
        if sheet is None and xl.sheet_names:
            sheet = xl.sheet_names[0]

        df = pd.read_excel(uploaded_file, sheet_name=sheet)
        df.columns = df.columns.str.strip()

        # Try common column name patterns
        dept_col    = next((c for c in df.columns if "dept" in c.lower() or "department" in c.lower()), None)
        access_col  = next((c for c in df.columns if "forbidden" in c.lower() or "access" in c.lower() or "level" in c.lower()), None)

        if not dept_col or not access_col:
            return {}, f"Could not find Department and Forbidden columns. Found: {list(df.columns)}"

        rules = {}
        for _, row in df.iterrows():
            dept    = str(row[dept_col]).strip()
            raw     = str(row[access_col]).strip()
            if dept and dept.lower() not in ("nan","none",""):
                levels = [x.strip() for x in re.split(r"[,;/]", raw) if x.strip() and x.strip().lower() not in ("nan","none","")]
                if levels:
                    rules[dept] = levels
        return rules, None

    except Exception as e:
        return {}, str(e)


# ─────────────────────────────────────────────────────────────────────────────
#  FEATURE 3+5: CLAUDE API — professional audit memo + executive summary
# ─────────────────────────────────────────────────────────────────────────────
def generate_ai_opinion(findings_df, meta, scope_start, scope_end, total_pop, in_scope_count):
    """
    Use AI to write a professional audit memo.
    Falls back to the rule-based opinion if the API call fails.
    """
    import requests

    total    = len(findings_df)
    critical = len(findings_df[findings_df["Severity"] == "🔴 CRITICAL"]) if total else 0
    high     = len(findings_df[findings_df["Severity"] == "🟠 HIGH"])     if total else 0
    medium   = len(findings_df[findings_df["Severity"] == "🟡 MEDIUM"])   if total else 0
    error_rate = round((total / in_scope_count * 100), 1) if in_scope_count > 0 else 0

    # Top 3 most frequent issue types
    if total > 0:
        top3 = findings_df["IssueType"].value_counts().head(3).to_dict()
        top3_str = ", ".join(f"{k} ({v} findings)" for k,v in top3.items())
    else:
        top3_str = "No findings"

    # Department breakdown
    if total > 0 and "Department" in findings_df.columns:
        dept_breakdown = findings_df["Department"].value_counts().head(5).to_dict()
        dept_str = ", ".join(f"{k}: {v}" for k,v in dept_breakdown.items())
    else:
        dept_str = "Not available"

    prompt = f"""You are a Senior IT Auditor writing a professional audit memo for a board-level audience.

ENGAGEMENT DATA:
- Client: {meta.get('client', 'Nairs.com Ltd')}
- Engagement Reference: {meta.get('ref', 'N/A')}
- Lead Auditor: {meta.get('auditor', 'N/A')}
- Audit Standard: {meta.get('standard', 'ISO 27001:2022')}
- Review Period: {scope_start.strftime('%d %B %Y')} to {scope_end.strftime('%d %B %Y')}
- Total population tested: {in_scope_count:,} system accounts
- Total findings: {total}
- Critical findings: {critical}
- High findings: {high}
- Medium findings: {medium}
- Overall error rate: {error_rate}%
- Top 3 issue types: {top3_str}
- Findings by department: {dept_str}

Write a professional audit memo with exactly these three sections:

**SECTION 1 — EXECUTIVE SUMMARY** (2 paragraphs)
Describe the overall risk posture. Mention the error rate. Reference the most impactful finding types. 
Use language appropriate for a board-level or CISO audience.

**SECTION 2 — KEY FINDINGS BREAKDOWN** (bullet points)
Cover the top 3 most frequent finding types. For each one, state what was found, what the risk is, 
and what ISO 27001:2022 control applies. Keep each bullet to 2-3 sentences.

**SECTION 3 — FORMAL AUDIT OPINION**
Issue one of: "Adverse" (5+ Criticals), "Qualified" (any Critical or 5+ High), 
"Emphasis of Matter" (any High), or "Unqualified" (no Criticals or Highs).
Write a formal opinion paragraph in standard audit language. 
State the opinion clearly and explain what it means for the organisation.

Format your response in clean markdown that will render well in Streamlit.
Do not include any preamble — start directly with the first section heading.
Today's date: {datetime.today().strftime('%d %B %Y')}"""

    try:
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"Content-Type": "application/json"},
            json={
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 1500,
                "messages": [{"role": "user", "content": prompt}]
            }
        )
        if response.status_code == 200:
            return response.json()["content"][0]["text"], True
        else:
            return None, False
    except Exception:
        return None, False


# ─────────────────────────────────────────────────────────────────────────────
#  FEATURE 4: EVIDENCE SAMPLER — 25-item audit sample for external auditors
# ─────────────────────────────────────────────────────────────────────────────
def generate_audit_sample(findings_df, sample_size=25):
    """
    Produces a prioritised sample of findings for external auditor review.
    Priority: Critical first → High → random Medium to fill to sample_size.
    Returns a DataFrame of sample_size rows (or fewer if not enough findings).
    """
    if findings_df.empty:
        return pd.DataFrame()

    critical = findings_df[findings_df["Severity"] == "🔴 CRITICAL"].copy()
    high     = findings_df[findings_df["Severity"] == "🟠 HIGH"].copy()
    medium   = findings_df[findings_df["Severity"] == "🟡 MEDIUM"].copy()

    sample = pd.DataFrame()

    # Take all Criticals first (up to sample_size)
    take_crit = min(len(critical), sample_size)
    if take_crit > 0:
        sample = pd.concat([sample, critical.head(take_crit)])

    # Fill with Highs
    remaining = sample_size - len(sample)
    if remaining > 0 and len(high) > 0:
        take_high = min(len(high), remaining)
        sample = pd.concat([sample, high.head(take_high)])

    # Fill remainder with random Mediums
    remaining = sample_size - len(sample)
    if remaining > 0 and len(medium) > 0:
        take_med = min(len(medium), remaining)
        sample = pd.concat([sample, medium.sample(take_med, random_state=42)])

    # Add sample metadata columns
    sample = sample.reset_index(drop=True)
    sample.insert(0, "Sample#",       range(1, len(sample)+1))
    sample.insert(1, "TestInstruction", sample["IssueType"].map({
        "Orphaned Account":                        "Verify email does not exist in current HR system. Confirm account is disabled or deleted.",
        "Terminated Employee with Active Account": "Confirm termination date in HR. Verify account was disabled within 24h per JML procedure.",
        "Post-Termination Login":                  "Pull AD login audit log. Confirm login timestamp vs termination date. Escalate to Legal.",
        "Toxic Access (SoD Violation)":            "Confirm current role from HR. Verify access level in live system. Request written CISO approval or escalate.",
        "Dormant Account":                         "Confirm last login date from system extract. Check with line manager if access is still required.",
        "MFA Not Enabled":                         "Log into identity portal. Confirm MFA status. Verify against MFA rollout register.",
        "Password Never Expired":                  "Confirm PasswordLastSet from AD. Verify against password policy requirement.",
        "Duplicate System Access":                 "Confirm both account IDs exist in live system. Identify primary account and request disable of duplicate.",
        "Contractor Without Expiry Date":          "Obtain contract from Procurement. Confirm end date. Set account expiry in system.",
        "Privilege Creep":                         "Pull full role history from IT. Confirm which roles are still needed with line manager.",
        "Shared / Generic Account":                "Identify all individuals using this account. Provision named accounts. Disable shared account.",
        "Service / System Account":                "Identify system/application using this account. Confirm named owner. Review permissions.",
        "Super-User / Admin Access":               "Request written CISO justification. Confirm in exception register. Downgrade if unjustified.",
        "Excessive Multi-System Access":           "List all systems. Send to line manager for recertification. Remove unconfirmed access.",
        "Near-Match Email":                        "Cross-check with HR. Contact employee directly. Confirm ownership or treat as orphaned.",
    }).fillna("Verify finding against source data and policy. Document evidence of testing."))
    sample.insert(2, "EvidenceRequired", "Screenshot of live system + HR record extract + written confirmation from system owner")
    sample.insert(3, "TestedBy",         "")
    sample.insert(4, "TestDate",         "")
    sample.insert(5, "TestResult",       "")
    sample.insert(6, "AuditorNote",      "")

    return sample


# ─────────────────────────────────────────────────────────────────────────────
#  FEATURE 4: Add Audit_Sample sheet to Excel export (helper)
# ─────────────────────────────────────────────────────────────────────────────
def add_sample_sheet(writer, sample_df, wb, H, R, O, Y):
    """Write the Audit_Sample_Request sheet into an open ExcelWriter."""
    if sample_df is None or sample_df.empty:
        return
    clean = sample_df[[c for c in sample_df.columns if not c.startswith("_")]].copy()
    clean.to_excel(writer, index=False, sheet_name="Audit_Sample_Request")
    ws = writer.sheets["Audit_Sample_Request"]

    # Column widths
    widths = {"Sample#":8,"TestInstruction":55,"EvidenceRequired":40,"TestedBy":18,
              "TestDate":14,"TestResult":16,"AuditorNote":36,
              "Severity":14,"IssueType":28,"Email":36,"FullName":24,"Department":18}
    for ci, col in enumerate(clean.columns):
        ws.set_column(ci, ci, widths.get(col, 16))

    # Header row
    for ci, col in enumerate(clean.columns):
        ws.write(0, ci, col, H)

    # Row colours by severity
    for ri, (_, row) in enumerate(clean.iterrows(), start=1):
        s = str(row.get("Severity",""))
        fmt = R if "CRITICAL" in s else (O if "HIGH" in s else (Y if "MEDIUM" in s else None))
        if fmt:
            ws.set_row(ri, None, fmt)



# ─────────────────────────────────────────────────────────────────────────────
#  RBAC MATRIX PARSER
# ─────────────────────────────────────────────────────────────────────────────
def load_rbac_matrix(uploaded_file):
    """
    Read an RBAC Matrix Excel file.
    Expected columns: JobTitle, System (optional), PermittedAccess
    Returns dict: {job_title: [permitted_access_levels]}
    Also accepts: {job_title: {system: permitted_access}}

    Example file:
      JobTitle          | System           | PermittedAccess
      Finance Manager   | SAP Finance      | Full Access
      Finance Manager   | Active Directory | Read Only
      Sales Executive   | CRM              | Full Access
    """
    try:
        uploaded_file.seek(0)
        df = pd.read_excel(uploaded_file)
        df.columns = df.columns.str.strip()

        # Flexible column detection — handles both JobTitle and FullName columns
        title_col  = next((c for c in df.columns if any(k in c.lower() for k in
                           ["job","title","role","position","designation",
                            "name","fullname","full_name","employee","user"])), None)
        access_col = next((c for c in df.columns if any(k in c.lower() for k in
                           ["permitted","access","level","entitlement","right",
                            "permission","allow","grant"])), None)
        system_col = next((c for c in df.columns if any(k in c.lower() for k in
                           ["system","application","app","platform"])), None)

        if not title_col or not access_col:
            return {}, f"Could not detect JobTitle/Name and PermittedAccess columns. Found: {list(df.columns)}"

        matrix = {}
        for _, row in df.iterrows():
            job   = str(row[title_col]).strip()
            perms = str(row[access_col]).strip()
            if job.lower() in ("nan","none","") or perms.lower() in ("nan","none",""):
                continue
            # Parse comma-separated permitted levels
            levels = [p.strip() for p in perms.split(",") if p.strip()]
            if job not in matrix:
                matrix[job] = []
            matrix[job].extend(levels)
            # Deduplicate
            matrix[job] = list(set(matrix[job]))

        return matrix, None

    except Exception as e:
        return {}, str(e)


# ─────────────────────────────────────────────────────────────────────────────
#  PRIVILEGED USER REGISTRY LOADER
# ─────────────────────────────────────────────────────────────────────────────
def load_privileged_registry(uploaded_file):
    """
    Read a Privileged User Registry Excel file.
    Expected columns: Email, AccessLevel, Owner, Justification,
                      ApprovedBy, LastReviewDate
    Returns a DataFrame of registered privileged accounts.

    Example file:
      Email                  | AccessLevel | Owner       | LastReviewDate
      john.smith@nairs.com   | Admin       | John Smith  | 2025-01-15
      svc.backup@nairs.com   | DBAdmin     | IT Manager  | 2024-06-01
    """
    try:
        uploaded_file.seek(0)
        df = pd.read_excel(uploaded_file)
        df.columns = df.columns.str.strip()

        # Flexible column detection
        email_col  = next((c for c in df.columns if "email" in c.lower() or
                           "account" in c.lower()), None)
        access_col = next((c for c in df.columns if any(k in c.lower() for k in
                           ["access","level","role","privilege"])), None)
        review_col = next((c for c in df.columns if any(k in c.lower() for k in
                           ["review","last","date","renewed"])), None)

        if not email_col:
            return None, f"Could not detect Email/Account column. Found: {list(df.columns)}"

        # Normalise email column
        df["_email_norm"] = df[email_col].str.strip().str.lower()

        # Parse review date if present
        if review_col:
            df["_review_date"] = pd.to_datetime(df[review_col], errors="coerce")
        else:
            df["_review_date"] = None

        return df, None

    except Exception as e:
        return None, str(e)


# ─────────────────────────────────────────────────────────────────────────────
#  RBAC CHECK — run against full system df
# ─────────────────────────────────────────────────────────────────────────────
def run_rbac_checks(sys_df, hr_df, rbac_matrix, selected_fw, today_dt):
    """
    Compare each account's actual access against what their job title
    permits in the RBAC Matrix. Returns list of finding dicts.
    """
    findings = []
    if not rbac_matrix or sys_df.empty or hr_df.empty:
        return findings

    hr = hr_df.copy()
    hr["_em"] = hr["Email"].str.strip().str.lower()
    hr = hr.drop_duplicates(subset="_em", keep="first")
    hr_lkp = hr.set_index("_em")

    sys = sys_df.copy()
    sys["_em"] = sys["Email"].str.strip().str.lower()

    for _, row in sys.iterrows():
        u_email  = str(row.get("Email","")).strip().lower()
        u_access = str(row.get("AccessLevel","")).strip()
        row_dict = row.to_dict()

        # Only check accounts that exist in HR
        if u_email not in set(hr["_em"]):
            continue

        hr_row   = hr_lkp.loc[u_email]
        job      = str(hr_row.get("JobTitle","")).strip()
        emp_stat = str(hr_row.get("EmploymentStatus","Active")).strip().lower()
        # Normalise dept for consistent matching
        _raw_dept_rbac = str(hr_row.get("Department","")).strip()
        _dept_rbac = normalise_dept(_raw_dept_rbac)

        # Skip terminated employees — handled by other checks
        if emp_stat in ("terminated","resigned","inactive"):
            continue

        if not job or job.lower() in ("nan","none","unknown",""):
            continue

        # Find permitted access for this job title
        permitted = rbac_matrix.get(job, [])
        if not permitted:
            continue  # Job not in matrix — cannot assess

        # Parse actual access levels (comma-separated)
        actual_levels = [a.strip() for a in u_access.split(",") if a.strip()]

        # Normalise actual access levels for intelligent comparison
        _norm_actual = normalise_access(u_access)
        _norm_permitted = []
        for p in permitted:
            _norm_permitted.extend(normalise_access(p))

        # Check each actual level against permitted list
        violations = []
        for level in actual_levels:
            _norm_level = normalise_access(level)
            _norm_level_canonical = _norm_level[0] if _norm_level else level
            # Check if this level is permitted
            is_permitted = (
                _norm_level_canonical in _norm_permitted or
                level.lower() in [p.lower() for p in permitted] or
                any(level.lower() in p.lower() or p.lower() in level.lower()
                    for p in permitted)
            )
            if not is_permitted:
                violations.append(level)

        if violations:
            findings.append(make_finding(
                row_dict,
                "RBAC Violation",
                f"'{job}' is permitted {permitted} per RBAC Matrix but holds "
                f"'{', '.join(violations)}' — access exceeds role entitlement. "
                f"Actual access: '{u_access}'.",
                selected_fw=selected_fw,
            ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  PRIVILEGED USER REGISTRY CHECK
# ─────────────────────────────────────────────────────────────────────────────
def run_registry_checks(sys_df, hr_df, registry_df, selected_fw, today_dt):
    """
    Cross-reference every privileged account found in the system
    against the Privileged User Registry.
    Flags:
      - Privileged accounts NOT in the registry (unauthorised)
      - Registry entries whose review date is > 12 months ago (overdue)
    """
    findings = []
    if registry_df is None or sys_df.empty:
        return findings

    from datetime import timedelta
    REVIEW_THRESHOLD_DAYS = 365

    reg_emails  = set(registry_df["_email_norm"].dropna())
    sys = sys_df.copy()
    sys["_em"] = sys["Email"].str.strip().str.lower()

    # Build HR lookup for employment status
    hr = hr_df.copy()
    hr["_em"] = hr["Email"].str.strip().str.lower()
    hr = hr.drop_duplicates(subset="_em", keep="first")
    hr_em_set = set(hr["_em"])
    hr_lkp = hr.set_index("_em")

    checked_for_overdue = set()  # avoid duplicate overdue findings

    for _, row in sys.iterrows():
        u_email  = str(row.get("Email","")).strip().lower()
        u_access = str(row.get("AccessLevel","Not specified")).strip()
        _raw_name = str(row.get("FullName","")).strip()
        if _raw_name and _raw_name.lower() not in ("nan","none",""):
            u_name = _raw_name
        else:
            _prefix = u_email.split("@")[0] if "@" in u_email else u_email
            u_name = _prefix.replace(".", " ").replace("_", " ").title()
        row_dict = row.to_dict()
        if not row_dict.get("FullName") or str(row_dict.get("FullName","")).lower() in ("nan","none",""):
            row_dict["FullName"] = u_name

        # Only check privileged accounts
        is_privileged = any(
            hr_kw.lower() in u_access.lower()
            for hr_kw in HIGH_RISK_ACCESS
        )
        if not is_privileged:
            continue

        # Skip terminated employees
        if u_email in hr_em_set:
            hr_row   = hr_lkp.loc[u_email]
            emp_stat = str(hr_row.get("EmploymentStatus","Active")).strip().lower()
            if emp_stat in ("terminated","resigned","inactive"):
                continue

        # Check 1: Is this account in the registry?
        if u_email not in reg_emails:
            findings.append(make_finding(
                row_dict,
                "Unauthorised Privileged Account",
                f"'{u_name}' holds privileged access '{u_access}' but does NOT appear "
                f"in the Privileged User Registry. No documented approval, justification "
                f"or named owner on record.",
                selected_fw=selected_fw,
            ))
        else:
            # Check 2: Is the review date current?
            reg_row = registry_df[registry_df["_email_norm"] == u_email].iloc[0]
            review_date = reg_row.get("_review_date")

            if u_email not in checked_for_overdue:
                checked_for_overdue.add(u_email)
                if review_date is not None and not pd.isna(review_date):
                    days_since = (today_dt - review_date).days
                    if days_since > REVIEW_THRESHOLD_DAYS:
                        findings.append(make_finding(
                            row_dict,
                            "Privileged Account Review Overdue",
                            f"'{u_name}' holds privileged access '{u_access}'. "
                            f"Last registry review was {days_since} days ago "
                            f"({review_date.strftime('%d %b %Y')}). "
                            f"Policy requires review every 12 months.",
                            selected_fw=selected_fw,
                        ))
                elif review_date is None or pd.isna(review_date):
                    findings.append(make_finding(
                        row_dict,
                        "Privileged Account Review Overdue",
                        f"'{u_name}' holds privileged access '{u_access}'. "
                        f"Privileged User Registry entry has no LastReviewDate recorded. "
                        f"Cannot confirm this account has ever been formally reviewed.",
                        selected_fw=selected_fw,
                    ))

    return findings

# ── Document parsing helpers ──────────────────────────────────────────────────

def extract_text(uploaded_file, max_chars=5000):
    """Extract text from PDF, DOCX, TXT or XLSX. Returns empty string on failure."""
    if uploaded_file is None:
        return ""
    name = uploaded_file.name.lower()
    try:
        if name.endswith(".txt"):
            return uploaded_file.read().decode("utf-8", errors="ignore")[:max_chars]
        elif name.endswith(".pdf"):
            try:
                import pypdf
                reader = pypdf.PdfReader(uploaded_file)
                text = " ".join(p.extract_text() or "" for p in reader.pages[:10])
                return text[:max_chars]
            except Exception:
                return "[PDF uploaded — install pypdf to extract content]"
        elif name.endswith(".docx"):
            try:
                import docx
                doc = docx.Document(uploaded_file)
                return " ".join(p.text for p in doc.paragraphs)[:max_chars]
            except Exception:
                return "[DOCX uploaded — install python-docx to extract content]"
        elif name.endswith((".xlsx",".xls")):
            df = pd.read_excel(uploaded_file, sheet_name=None)
            text_parts = []
            for sheet_name, sheet_df in df.items():
                text_parts.append(f"[Sheet: {sheet_name}]")
                text_parts.append(sheet_df.to_string(index=False))
            return " ".join(text_parts)[:max_chars]
        elif name.endswith(".csv"):
            df = pd.read_csv(uploaded_file)
            return df.to_string(index=False)[:max_chars]
    except Exception as e:
        return f"[Could not parse {uploaded_file.name}: {e}]"
    return ""

def detect_doc_type(f):
    """
    Auto-detect document type from filename.
    Returns one of: hr_master | system_access | soa | access_policy |
                    jml_procedure | risk_register | other
    """
    if f is None:
        return "other"
    name = f.name.lower()
    if any(k in name for k in ["hr_master","hr master","hrmaster","employee","staff_list","staff list","personnel"]):
        return "hr_master"
    if any(k in name for k in ["system_access","system access","access_list","access list","user_access","useraccess","sysaccess"]):
        return "system_access"
    if any(k in name for k in ["soa","statement_of_applicability","statement of applicability","annex_a","annex a"]):
        return "soa"
    if any(k in name for k in ["access_policy","access policy","access_control","access control policy"]):
        return "access_policy"
    if any(k in name for k in ["jml","joiner","mover","leaver","onboard","offboard","joinermover"]):
        return "jml_procedure"
    if any(k in name for k in ["risk_register","risk register","riskregister"]):
        return "risk_register"
    if any(k in name for k in ["rbac","role_matrix","role matrix","access_matrix","entitlement","permission_matrix"]):
        return "rbac_matrix"
    if any(k in name for k in ["privileged","priv_register","priv register","admin_register","privileged_user","privileged user"]):
        return "privileged_registry"
    if any(k in name for k in ["ual","active_directory","active directory","ad_export","user_access_list"]):
        return "system_access"
    if any(k in name for k in ["iso","standard","policy","procedure","framework","gdpr","sox","pci"]):
        return "standard"
    return "other"

def parse_soa_sod_rules(soa_text):
    """
    Try to extract SoD rules from uploaded SOA/policy text.
    Returns a dict of {dept: [forbidden_access_levels]} or empty dict.
    """
    import re
    rules = {}
    # Look for patterns like "Finance: Admin, DBAdmin" or "Sales staff: Finance, Payroll"
    dept_keywords = ["Finance","IT","HR","Sales","Marketing","Operations","Procurement","Legal","Risk","Support"]
    access_keywords = ["Admin","Finance","Payroll","DBAdmin","HR","SysAdmin","FullControl","SuperAdmin","Root"]
    for dept in dept_keywords:
        pattern = rf"{dept}[^.\n]{{0,60}}({"|".join(access_keywords)})"
        matches = re.findall(pattern, soa_text, re.IGNORECASE)
        if matches:
            rules[dept] = list(set(matches))
    return rules

