import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'

const resources = {
  en: {
    translation: {
      // App
      'app.general.title': 'CloudTrail Analyzer',
      'app.general.selectView': 'Select a view from the sidebar to get started.',

      // Sidebar
      'app.nav.cloudtrail': 'CloudTrail',
      'app.nav.securityInsights': 'Security Insights',
      'app.nav.lightMode': 'Light mode',
      'app.nav.darkMode': 'Dark mode',

      // Navigation
      'app.nav.account': 'Account:',
      'app.nav.region': 'Region:',

      // Dashboard
      'security.dashboard.title': 'Security Findings',
      'security.dashboard.accountInfo': '{{earliest}} — {{latest}} UTC · {{count}} events analyzed',
      'security.dashboard.analyzing': 'Analyzing CloudTrail events...',
      'security.dashboard.retry': 'Retry',
      'security.dashboard.refresh': 'Refresh',
      'security.dashboard.filter': 'Filter:',
      'security.dashboard.hourlyActivity': 'Hourly Activity (UTC)',
      'security.dashboard.identityTypes': 'Identity Types',
      'security.dashboard.runningQuery': 'Running query...',
      'security.dashboard.openInQueryView': 'Open in Query View',
      'security.dashboard.noEvents': 'No events found for this finding.',
      'security.dashboard.showSql': 'Show SQL',
      'security.dashboard.results': '{{count}} results',

      // Investigate
      'security.investigate.title': 'Investigate',
      'security.investigate.scenarios': '{{count}} investigation scenarios',
      'security.investigate.crossAccount': 'Cross-account enabled',
      'security.investigate.selectScenario': 'Select an investigation scenario from the left',
      'security.investigate.queriesRunAgainst': 'Queries run against all synced CloudTrail logs',
      'security.investigate.requires': 'Requires: {{label}}',
      'security.investigate.selectOrType': 'Select or type below...',
      'security.investigate.runInvestigation': 'Run Investigation',
      'security.investigate.running': 'Running...',
      'security.investigate.queryError': 'Query Error',
      'security.investigate.noResults': 'No results found for this investigation.',
      'security.investigate.noResultsHint': 'This could mean no matching events exist in the synced data.',
      'security.investigate.showSqlQuery': 'Show SQL query',
      'security.investigate.allCategories': 'All Categories',

      // S3 Sync
      'data.sync.title': 'S3 Sync',
      'data.sync.accountsSelected': '{{count}} account(s) selected',
      'data.sync.configIncomplete': 'Configuration Incomplete',
      'data.sync.goToSettings': 'Go to Settings → S3 Config to configure bucket and select accounts.',
      'data.sync.newSync': 'New Sync',
      'data.sync.accountsToDownload': 'Accounts to download:',
      'data.sync.noAccountsSelected': 'No accounts selected. Go to S3 Config to select accounts.',
      'data.sync.startDate': 'Start Date',
      'data.sync.endDate': 'End Date',
      'data.sync.startSync': 'Start Sync ({{count}} account(s))',
      'data.sync.syncing': 'Syncing {{count}} accounts...',
      'data.sync.activeDownloads': 'Active Downloads',
      'data.sync.syncHistory': 'Sync History',
      'data.sync.noCompleted': 'No completed syncs yet.',
      'data.sync.account': 'Account',
      'data.sync.dateRange': 'Date Range',
      'data.sync.files': 'Files',
      'data.sync.sizeOnDisk': 'Size on Disk',
      'data.sync.lastUpdated': 'Last Updated',
      'data.sync.status': 'Status',

      // S3 Config
      'settings.s3config.title': 'S3 Connection',
      'settings.s3config.subtitle': 'Configure bucket, select account. Date range is chosen when you sync.',
      'settings.s3config.callerIdentity': 'Caller Identity',
      'settings.s3config.fetching': 'Fetching...',
      'settings.s3config.accountMode': 'Account Mode',
      'settings.s3config.singleAccount': 'Single Account',
      'settings.s3config.oneAccount': 'One AWS account',
      'settings.s3config.controlTower': 'Control Tower',
      'settings.s3config.multiAccount': 'Multi-account (Org)',
      'settings.s3config.bucketName': 'Bucket Name',
      'settings.s3config.bucketRegion': 'Bucket Region',
      'settings.s3config.orgId': 'Organization ID',
      'settings.s3config.detectStructure': 'Detect Bucket Structure',
      'settings.s3config.detecting': 'Detecting...',
      'settings.s3config.targetAccounts': 'Target Accounts',
      'settings.s3config.discover': 'Discover',
      'settings.s3config.discovering': 'Discovering...',
      'settings.s3config.selectAll': 'Select All ({{count}} accounts)',
      'settings.s3config.clickDiscover': 'Click "Detect Bucket Structure" above or "Discover" to find member accounts.',
      'settings.s3config.accountsSelected': '{{count}} account(s) selected for sync',
      'settings.s3config.save': 'Save',
      'settings.s3config.testConnection': 'Test Connection',
      'settings.s3config.accessible': 'Accessible',
      'settings.s3config.failed': 'Failed',
      'settings.s3config.saved': 'Configuration saved',

      // Credentials
      'settings.credentials.title': 'AWS Credentials',
      'settings.credentials.subtitle': 'Only the selected method is used — no fallback',
      'settings.credentials.authMethod': 'Auth Method',
      'settings.credentials.active': 'Active',
      'settings.credentials.activate': 'Activate',
      'settings.credentials.sessionCreds': 'Session Credentials (SSO)',
      'settings.credentials.savedActive': 'Saved credentials active (key: {{key}}...)',
      'settings.credentials.pasteInstructions': 'Copy these from your AWS SSO portal → Account → Access keys. They are temporary and expire in 1–12 hours. Paste new ones when they expire.',
      'settings.credentials.accessKeyId': 'Access Key ID',
      'settings.credentials.secretAccessKey': 'Secret Access Key',
      'settings.credentials.sessionToken': 'Session Token',
      'settings.credentials.savedToConfig': 'Credentials are saved to config and restored on app restart (valid for 1–12 hours).',
      'settings.credentials.applyValidate': 'Apply & Validate',
      'settings.credentials.ssoConfig': 'SSO Profile Configuration',
      'settings.credentials.profileName': 'AWS Profile Name',
      'settings.credentials.ssoLogin': 'Run aws sso login --profile {{profile}} in your terminal to authenticate.',
      'settings.credentials.saveValidate': 'Save & Validate',
      'settings.credentials.enterCreds': 'Enter Credentials',
      'settings.credentials.imdsNote': 'No configuration needed. This will set IMDS v2 as the active credential method.',
      'settings.credentials.applying': 'Applying credentials...',
      'settings.credentials.validating': 'Validating credentials...',
      'settings.credentials.validationFailed': 'Validation Failed',
      'settings.credentials.dismiss': 'Dismiss',
      'settings.credentials.credentialsActive': 'Credentials Active',
      'settings.credentials.credentialsFailed': 'Credentials Failed',
      'settings.credentials.source': 'Source:',
      'settings.credentials.result': 'Result',
      'settings.credentials.back': 'Back',

      // LLM Config
      'settings.llm.title': 'AI / LLM Provider',
      'settings.llm.subtitle': 'Configure which LLM generates DuckDB SQL from your natural language queries. The dashboard and pre-built findings work without any LLM.',
      'settings.llm.apiKey': 'API Key',
      'settings.llm.apiKeyConfigured': 'API key already configured',
      'settings.llm.model': 'Model',
      'settings.llm.customEndpoint': 'Custom Endpoint URL',
      'settings.llm.azureNote': 'For Azure OpenAI, corporate proxies, or any OpenAI-compatible API',
      'settings.llm.ollamaNote': 'On first query, the app will automatically install Ollama (if needed) and pull the codellama:7b model (~4GB download). Subsequent queries are instant.',
      'settings.llm.ollamaEndpoint': 'Ollama Endpoint',
      'settings.llm.bedrockNote': 'Uses the AWS credentials configured in the Credentials tab. Model:',
      'settings.llm.saveActivate': 'Save & Activate',
      'settings.llm.active': 'Active',
      'settings.llm.saving': 'Saving...',
      'settings.llm.saved': 'Saved!',

      // System
      'settings.system.title': 'System Status',
      'settings.system.loading': 'Loading system status...',
      'settings.system.loadFailed': 'Failed to load health status:',
      'settings.system.retry': 'Retry',
      'settings.system.refresh': 'Refresh',
      'settings.system.version': 'Version',
      'settings.system.uptime': 'Uptime',
      'settings.system.startupValidation': 'Startup Validation',
      'settings.system.noChecks': 'No validation checks available.',

      // PreBuilt (legacy)
      'security.prebuilt.account': 'Account:',
      'security.prebuilt.region': 'Region:',
      'security.prebuilt.dates': 'Dates:',
      'security.prebuilt.loading': 'Loading templates...',
      'security.prebuilt.retry': 'Retry',
      'security.prebuilt.selectPrompt': 'Select a prompt template from the left',
      'security.prebuilt.placeholders': 'Placeholders will be filled from your S3 config',
      'security.prebuilt.loading2': 'Loading...',
      'security.prebuilt.prompt': 'Prompt (editable)',
      'security.prebuilt.emptyPlaceholders': 'Some placeholders are empty. Configure S3 settings first.',
      'security.prebuilt.generatedSql': 'Generated SQL',
      'security.prebuilt.error': 'Error',
      'security.prebuilt.noResults': 'Query returned no results.',
      'security.prebuilt.footer': 'Click "Run Query" to execute via Bedrock + DuckDB, or copy the prompt for use in kiro-cli.',

      // Chat
      'security.chat.title': 'Bedrock Chat',
      'security.chat.subtitle': 'AI-powered investigation',
      'security.chat.comingSoon': 'Coming Soon',

      // Query
      'security.query.sqlEditor': 'SQL Editor',
      'security.query.subtitle': 'Query CloudTrail logs with DuckDB',
      'security.query.comingSoon': 'Coming Soon',
      'security.query.nlQuery': 'NL Query',
      'security.query.nlSubtitle': 'Natural language to SQL',
    }
  }
}

i18n
  .use(initReactI18next)
  .init({
    resources,
    lng: 'en',
    interpolation: {
      escapeValue: false,
    },
  })

export default i18n
