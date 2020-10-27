module.exports = {
  /**
   * Name of the integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @required
   */
  name: 'AttackerKB Topic Search',
  /**
   * The acronym that appears in the notification window when information from this integration
   * is displayed.  Note that the acronym is included as part of each "tag" in the summary information
   * for the integration.  As a result, it is best to keep it to 4 or less characters.  The casing used
   * here will be carried forward into the notification window.
   *
   * @type String
   * @required
   */
  acronym: 'ATTACK',
  /**
   * Description for this integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @optional
   */
  description: 'This integration queries CVE IDs against the AttackerKB Topic API.',
  entityTypes: ['cve'],
  styles: ['./styles/style.less'],
  /**
   * Provide custom component logic and template for rendering the integration details block.  If you do not
   * provide a custom template and/or component then the integration will display data as a table of key value
   * pairs.
   *
   * @type Object
   * @optional
   */
  block: {
    component: {
      file: './components/block.js'
    },
    template: {
      file: './templates/block.hbs'
    }
  },
  summary: {
    component: {
      file: './components/summary.js'
    },
    template: {
      file: './templates/summary.hbs'
    }
  },
  onDemandOnly: true,
  request: {
    // Provide the path to your certFile. Leave an empty string to ignore this option.
    // Relative paths are relative to the Urlhaus integration's root directory
    cert: '',
    // Provide the path to your private key. Leave an empty string to ignore this option.
    // Relative paths are relative to the Urlhaus integration's root directory
    key: '',
    // Provide the key passphrase if required.  Leave an empty string to ignore this option.
    // Relative paths are relative to the Urlhaus integration's root directory
    passphrase: '',
    // Provide the Certificate Authority. Leave an empty string to ignore this option.
    // Relative paths are relative to the Urlhaus integration's root directory
    ca: '',
    // An HTTP proxy to be used. Supports proxy Auth with Basic Auth, identical to support for
    // the url parameter (by embedding the auth info in the uri)
    proxy: '',

    rejectUnauthorized: true
  },
  logging: {
    level: 'info' //trace, debug, info, warn, error, fatal
  },
  /**
   * Options that are displayed to the user/admin in the Polarity integration user-interface.  Should be structured
   * as an array of option objects.
   *
   * @type Array
   * @optional
   */
  options: [
    {
      key: 'apiKey',
      name: 'Valid AttackerKB API Key',
      description: 'Valid AttackerKB API Key',
      default: '',
      type: 'password',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'resultCount',
      name: 'Maximum Number of Results',
      description:
        'The maximum number of API search results that will be displayed in the Polarity Overlay window. (Default: 5)',
      default: 5,
      type: 'number',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'publicOnly',
      name: 'Only Show Publicly Disclosed Vulnerabilities',
      description:
        'If checked, only vulnerabilites with a current state of PUBLIC will be returned.',
      default: true,
      type: 'boolean',
      userCanEdit: true,
      adminOnly: false
    }
  ]
};
