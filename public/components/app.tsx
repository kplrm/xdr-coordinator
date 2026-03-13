import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  EuiLoadingSpinner,
  EuiBadge,
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiCodeBlock,
  EuiFieldSearch,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutFooter,
  EuiFlyoutHeader,
  EuiForm,
  EuiFormRow,
  EuiHorizontalRule,
  EuiInMemoryTable,
  EuiPage,
  EuiPageBody,
  EuiPageHeader,
  EuiPagination,
  EuiPanel,
  EuiSelect,
  EuiSpacer,
  EuiSwitch,
  EuiTab,
  EuiTabs,
  EuiText,
  EuiTitle,
  EuiToolTip,
} from '@elastic/eui';
import { i18n } from '@osd/i18n';
import { BrowserRouter as Router } from 'react-router-dom';
import { CoreStart } from '../../../../src/core/public';
import {
  EnrollmentTokenStatusResponse,
  GenerateEnrollmentTokenResponse,
  ListAgentsResponse,
  ListEnrollmentTokensResponse,
  PolicyLogLevel,
  RunActionResponse,
  UpsertPolicyResponse,
  XdrAction,
  XdrAgent,
  XdrEnrollmentToken,
  XdrPolicy,
} from '../../common';

interface XdrManagerAppDeps {
  basename: string;
  notifications: CoreStart['notifications'];
  http: CoreStart['http'];
}

const statusColorMap: Record<string, 'success' | 'warning' | 'danger' | 'hollow'> = {
  healthy: 'success',
  degraded: 'warning',
  offline: 'danger',
  unseen: 'hollow',
};

const formatLastSeenAgo = (lastSeen: string, nowMs: number): string => {
  const lastSeenMs = Date.parse(lastSeen);
  if (!Number.isFinite(lastSeenMs)) {
    return i18n.translate('xdrManager.lastSeen.unknown', {
      defaultMessage: 'unknown',
    });
  }

  const diffSeconds = Math.max(0, Math.floor((nowMs - lastSeenMs) / 1000));

  if (diffSeconds < 60) {
    return i18n.translate('xdrManager.lastSeen.secondsAgo', {
      defaultMessage: '{count} sec ago',
      values: { count: diffSeconds },
    });
  }

  const diffMinutes = Math.floor(diffSeconds / 60);
  if (diffMinutes < 60) {
    return i18n.translate('xdrManager.lastSeen.minutesAgo', {
      defaultMessage: '{count} min ago',
      values: { count: diffMinutes },
    });
  }

  const diffHours = Math.floor(diffMinutes / 60);
  if (diffHours < 24) {
    return i18n.translate('xdrManager.lastSeen.hoursAgo', {
      defaultMessage: '{count} hr ago',
      values: { count: diffHours },
    });
  }

  const diffDays = Math.floor(diffHours / 24);
  const dayUnit = diffDays === 1 ? 'day' : 'days';
  return i18n.translate('xdrManager.lastSeen.daysAgo', {
    defaultMessage: '{count} {unit} ago',
    values: { count: diffDays, unit: dayUnit },
  });
};

export const XdrManagerApp = ({ basename, notifications, http }: XdrManagerAppDeps) => {
  const [agents, setAgents] = useState<XdrAgent[]>([]);
  const [policies, setPolicies] = useState<XdrPolicy[]>([]);
  const [latestVersion, setLatestVersion] = useState<string | undefined>(undefined);
  const [isLoading, setIsLoading] = useState(false);

  const [enrollmentTokensList, setEnrollmentTokensList] = useState<XdrEnrollmentToken[]>([]);
  const [isLoadingTokens, setIsLoadingTokens] = useState(false);

  const [isEnrollFlyoutOpen, setIsEnrollFlyoutOpen] = useState(false);
  const [policyId, setPolicyId] = useState('');
  const [tagsText, setTagsText] = useState('linux,production');
  const [enrollmentToken, setEnrollmentToken] = useState('');
  const [tokenPolicyId, setTokenPolicyId] = useState('');
  const [tokenConsumedHostname, setTokenConsumedHostname] = useState('');
  const [tokenValidationStatus, setTokenValidationStatus] = useState<'idle' | 'waiting' | 'consumed'>(
    'idle'
  );
  const [isGeneratingEnrollmentToken, setIsGeneratingEnrollmentToken] = useState(false);
  const [nowMs, setNowMs] = useState(() => Date.now());

  const [isPolicyFlyoutOpen, setIsPolicyFlyoutOpen] = useState(false);
  const [editingPolicyId, setEditingPolicyId] = useState<string | null>(null);
  const [policyNameInput, setPolicyNameInput] = useState('');
  const [policyDescriptionInput, setPolicyDescriptionInput] = useState('');
  const [policyLogLevel, setPolicyLogLevel] = useState<PolicyLogLevel>('standard');
  const [policyMalwareProtection, setPolicyMalwareProtection] = useState(true);
  const [policyFileIntegrity, setPolicyFileIntegrity] = useState(true);
  const [policyAutoUpgrade, setPolicyAutoUpgrade] = useState(false);
  const [policyOsqueryEnabled, setPolicyOsqueryEnabled] = useState(false);
  const [isSavingPolicy, setIsSavingPolicy] = useState(false);
  const [activeTab, setActiveTab] = useState<'agents' | 'policies' | 'tokens'>('agents');

  const [agentSearchQuery, setAgentSearchQuery] = useState('');
  const [agentPageSize, setAgentPageSize] = useState(10);
  const [agentPageIndex, setAgentPageIndex] = useState(0);

  const [policyPageSize, setPolicyPageSize] = useState(10);
  const [policyPageIndex, setPolicyPageIndex] = useState(0);

  const policyNameById = useMemo(
    () => Object.fromEntries(policies.map((policy) => [policy.id, policy.name])),
    [policies]
  );

  const loadData = useCallback(async (showErrorToast = true) => {
    setIsLoading(true);
    try {
      const response = await http.get<ListAgentsResponse>('/api/xdr_manager/agents');
      setAgents(response.agents);
      setPolicies(response.policies);
      if (response.latestVersion) {
        setLatestVersion(response.latestVersion);
      }
      if (!policyId && response.policies.length > 0) {
        setPolicyId(response.policies[0].id);
      }
    } catch (error) {
      if (showErrorToast) {
        notifications.toasts.addDanger({
          title: i18n.translate('xdrManager.loadDataError', {
            defaultMessage: 'Unable to load XDR data',
          }),
          text: error instanceof Error ? error.message : String(error),
        });
      }
    } finally {
      setIsLoading(false);
    }
  }, [http, notifications.toasts, policyId]);

  const loadEnrollmentTokens = useCallback(async () => {
    setIsLoadingTokens(true);
    try {
      const response = await http.get<ListEnrollmentTokensResponse>('/api/xdr_manager/enrollment_tokens');
      setEnrollmentTokensList(response.tokens);
    } catch (error) {
      notifications.toasts.addDanger({
        title: i18n.translate('xdrManager.loadTokensError', {
          defaultMessage: 'Unable to load enrollment tokens',
        }),
        text: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setIsLoadingTokens(false);
    }
  }, [http, notifications.toasts]);

  const removeAgent = useCallback(
    async (agent: XdrAgent) => {
      const confirmed = window.confirm(
        i18n.translate('xdrManager.removeAgentConfirm', {
          defaultMessage:
            'Remove agent "{name}"? The plugin will forget this agent and further heartbeats and telemetry from it will be rejected.',
          values: { name: agent.name },
        })
      );

      if (!confirmed) {
        return;
      }

      try {
        await http.delete(`/api/xdr_manager/agents/${agent.id}`);
        notifications.toasts.addSuccess(
          i18n.translate('xdrManager.agentRemoved', {
            defaultMessage: 'Agent "{name}" removed.',
            values: { name: agent.name },
          })
        );
        await loadData();
      } catch (error) {
        notifications.toasts.addDanger({
          title: i18n.translate('xdrManager.removeAgentError', {
            defaultMessage: 'Unable to remove agent',
          }),
          text: error instanceof Error ? error.message : String(error),
        });
      }
    },
    [http, loadData, notifications.toasts]
  );

  useEffect(() => {
    loadData();
  }, [loadData]);

  useEffect(() => {
    if (activeTab !== 'agents') {
      return;
    }

    const timer = window.setInterval(() => {
      loadData(false);
    }, 5000);

    return () => window.clearInterval(timer);
  }, [activeTab, loadData]);

  useEffect(() => {
    if (activeTab === 'tokens') {
      loadEnrollmentTokens();
    }
  }, [activeTab, loadEnrollmentTokens]);

  useEffect(() => {
    const timer = window.setInterval(() => {
      setNowMs(Date.now());
    }, 1000);

    return () => window.clearInterval(timer);
  }, []);

  const runAction = useCallback(
    async (agentId: string, action: XdrAction) => {
      try {
        const response = await http.post<RunActionResponse>(`/api/xdr_manager/agents/${agentId}/action`, {
          body: JSON.stringify({ action }),
        });
        setAgents((previous) =>
          previous.map((agent) => (agent.id === response.agent.id ? response.agent : agent))
        );
        notifications.toasts.addSuccess(response.message);
      } catch (error) {
        notifications.toasts.addDanger({
          title: i18n.translate('xdrManager.actionError', {
            defaultMessage: 'Unable to run action',
          }),
          text: error instanceof Error ? error.message : String(error),
        });
      }
    },
    [http, notifications.toasts]
  );

  const generateEnrollmentToken = useCallback(async () => {
    if (!policyId) {
      notifications.toasts.addWarning(
        i18n.translate('xdrManager.policyRequiredForToken', {
          defaultMessage: 'Select a policy before generating an enrollment token.',
        })
      );
      return;
    }

    setIsGeneratingEnrollmentToken(true);
    try {
      const response = await http.post<GenerateEnrollmentTokenResponse>('/api/xdr_manager/enrollment_tokens', {
        body: JSON.stringify({ policyId }),
      });

      setEnrollmentToken(response.token);
      setTokenPolicyId(response.policyId);
      setTokenConsumedHostname('');
      setTokenValidationStatus('waiting');

      notifications.toasts.addSuccess(
        i18n.translate('xdrManager.generateEnrollmentTokenSuccess', {
          defaultMessage: 'Enrollment token generated. Use it in xdr-agent enrollment_token.',
        })
      );
    } catch (error) {
      notifications.toasts.addDanger({
        title: i18n.translate('xdrManager.generateEnrollmentTokenError', {
          defaultMessage: 'Unable to generate enrollment token',
        }),
        text: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setIsGeneratingEnrollmentToken(false);
    }
  }, [http, notifications.toasts, policyId]);

  const stopEnrollmentValidation = useCallback(() => {
    setTokenValidationStatus('idle');
    setEnrollmentToken('');
    setTokenPolicyId('');
    setTokenConsumedHostname('');
  }, []);

  useEffect(() => {
    if (!isEnrollFlyoutOpen || !enrollmentToken || tokenValidationStatus !== 'waiting') {
      return;
    }

    let isMounted = true;

    const pollTokenStatus = async () => {
      try {
        const response = await http.get<EnrollmentTokenStatusResponse>(
          `/api/xdr_manager/enrollment_tokens/${encodeURIComponent(enrollmentToken)}/status`
        );

        if (!isMounted || response.status !== 'consumed') {
          return;
        }

        setTokenValidationStatus('consumed');
        setTokenConsumedHostname(response.consumedHostname ?? 'unknown');
        await loadData();
      } catch {
      }
    };

    pollTokenStatus();
    const timer = window.setInterval(pollTokenStatus, 1500);

    return () => {
      isMounted = false;
      window.clearInterval(timer);
    };
  }, [enrollmentToken, http, isEnrollFlyoutOpen, loadData, tokenValidationStatus]);

  const openCreatePolicyFlyout = useCallback(() => {
    setEditingPolicyId(null);
    setPolicyNameInput('');
    setPolicyDescriptionInput('');
    setPolicyLogLevel('standard');
    setPolicyMalwareProtection(true);
    setPolicyFileIntegrity(true);
    setPolicyAutoUpgrade(false);
    setPolicyOsqueryEnabled(false);
    setIsPolicyFlyoutOpen(true);
  }, []);

  const openEditPolicyFlyout = useCallback((policy: XdrPolicy) => {
    setEditingPolicyId(policy.id);
    setPolicyNameInput(policy.name);
    setPolicyDescriptionInput(policy.description);
    setPolicyLogLevel(policy.logLevel);
    setPolicyMalwareProtection(policy.malwareProtection);
    setPolicyFileIntegrity(policy.fileIntegrityMonitoring);
    setPolicyAutoUpgrade(policy.autoUpgrade);
    setPolicyOsqueryEnabled(policy.osqueryEnabled);
    setIsPolicyFlyoutOpen(true);
  }, []);

  const savePolicy = useCallback(async () => {
    if (!policyNameInput.trim() || !policyDescriptionInput.trim()) {
      notifications.toasts.addWarning(
        i18n.translate('xdrManager.policyValidation', {
          defaultMessage: 'Policy name and description are required.',
        })
      );
      return;
    }

    const body = JSON.stringify({
      name: policyNameInput.trim(),
      description: policyDescriptionInput.trim(),
      logLevel: policyLogLevel,
      malwareProtection: policyMalwareProtection,
      fileIntegrityMonitoring: policyFileIntegrity,
      autoUpgrade: policyAutoUpgrade,
      osqueryEnabled: policyOsqueryEnabled,
    });

    setIsSavingPolicy(true);
    try {
      if (editingPolicyId) {
        await http.put<UpsertPolicyResponse>(`/api/xdr_manager/policies/${editingPolicyId}`, { body });
        notifications.toasts.addSuccess(
          i18n.translate('xdrManager.policyUpdated', {
            defaultMessage: 'Policy updated.',
          })
        );
      } else {
        await http.post<UpsertPolicyResponse>('/api/xdr_manager/policies', { body });
        notifications.toasts.addSuccess(
          i18n.translate('xdrManager.policyCreated', {
            defaultMessage: 'Policy created.',
          })
        );
      }

      setIsPolicyFlyoutOpen(false);
      await loadData();
    } catch (error) {
      notifications.toasts.addDanger({
        title: i18n.translate('xdrManager.policySaveError', {
          defaultMessage: 'Unable to save policy',
        }),
        text: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setIsSavingPolicy(false);
    }
  }, [
    editingPolicyId,
    http,
    loadData,
    notifications.toasts,
    policyAutoUpgrade,
    policyDescriptionInput,
    policyFileIntegrity,
    policyLogLevel,
    policyMalwareProtection,
    policyNameInput,
    policyOsqueryEnabled,
  ]);

  const deletePolicy = useCallback(
    async (policy: XdrPolicy) => {
      const confirmed = window.confirm(
        i18n.translate('xdrManager.policyDeleteConfirm', {
          defaultMessage: 'Delete policy {name}? This only works when no agents are assigned.',
          values: { name: policy.name },
        })
      );

      if (!confirmed) {
        return;
      }

      try {
        await http.delete(`/api/xdr_manager/policies/${policy.id}`);
        notifications.toasts.addSuccess(
          i18n.translate('xdrManager.policyDeleted', {
            defaultMessage: 'Policy deleted.',
          })
        );
        await loadData();
      } catch (error) {
        notifications.toasts.addDanger({
          title: i18n.translate('xdrManager.policyDeleteError', {
            defaultMessage: 'Unable to delete policy',
          }),
          text: error instanceof Error ? error.message : String(error),
        });
      }
    },
    [http, loadData, notifications.toasts]
  );

  const columns = [
    {
      field: 'name',
      name: i18n.translate('xdrManager.column.name', { defaultMessage: 'Agent' }),
    },
    {
      name: i18n.translate('xdrManager.column.policy', { defaultMessage: 'Policy' }),
      render: (agent: XdrAgent) => policyNameById[agent.policyId] ?? agent.policyId,
    },
    {
      field: 'status',
      name: i18n.translate('xdrManager.column.status', { defaultMessage: 'Status' }),
      render: (status: string) => <EuiBadge color={statusColorMap[status] ?? 'hollow'}>{status}</EuiBadge>,
    },
    {
      field: 'version',
      name: i18n.translate('xdrManager.column.version', { defaultMessage: 'Version' }),
      render: (version: string) => {
        const hasUpgrade = latestVersion && version !== latestVersion;
        return (
          <EuiFlexGroup gutterSize="xs" alignItems="center" responsive={false}>
            <EuiFlexItem grow={false}>{version}</EuiFlexItem>
            {hasUpgrade && (
              <EuiFlexItem grow={false}>
                <EuiBadge color="warning">
                  {i18n.translate('xdrManager.upgradeAvailable', {
                    defaultMessage: 'v{latest} available',
                    values: { latest: latestVersion },
                  })}
                </EuiBadge>
              </EuiFlexItem>
            )}
          </EuiFlexGroup>
        );
      },
    },
    {
      field: 'lastSeen',
      name: i18n.translate('xdrManager.column.lastSeen', { defaultMessage: 'Last seen' }),
      render: (lastSeen: string) => formatLastSeenAgo(lastSeen, nowMs),
    },
    {
      name: i18n.translate('xdrManager.column.tags', { defaultMessage: 'Tags' }),
      render: (agent: XdrAgent) => agent.tags.join(', '),
    },
    {
      name: i18n.translate('xdrManager.column.actions', { defaultMessage: 'Actions' }),
      width: '200px',
      render: (agent: XdrAgent) => {
        const canUpgrade = Boolean(latestVersion && agent.version !== latestVersion);
        return (
          <EuiFlexGroup gutterSize="s" responsive={false}>
            <EuiFlexItem grow={false}>
              <EuiToolTip
                content={
                  canUpgrade
                    ? i18n.translate('xdrManager.action.upgradeTooltip', {
                        defaultMessage: 'Upgrade to v{version}',
                        values: { version: latestVersion },
                      })
                    : i18n.translate('xdrManager.action.upgradeTooltipCurrent', {
                        defaultMessage: 'Agent is already on the latest version',
                      })
                }
              >
                <EuiButtonEmpty
                  size="xs"
                  isDisabled={!canUpgrade}
                  onClick={() => runAction(agent.id, 'upgrade')}
                >
                  {i18n.translate('xdrManager.action.upgrade', { defaultMessage: 'Upgrade' })}
                </EuiButtonEmpty>
              </EuiToolTip>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButtonEmpty size="xs" color="danger" onClick={() => removeAgent(agent)}>
                {i18n.translate('xdrManager.action.remove', { defaultMessage: 'Remove' })}
              </EuiButtonEmpty>
            </EuiFlexItem>
          </EuiFlexGroup>
        );
      },
    },
  ];

  const policyColumns = [
    {
      field: 'name',
      name: i18n.translate('xdrManager.policyColumn.name', { defaultMessage: 'Policy' }),
    },
    {
      field: 'description',
      name: i18n.translate('xdrManager.policyColumn.description', { defaultMessage: 'Description' }),
    },
    {
      field: 'logLevel',
      name: i18n.translate('xdrManager.policyColumn.logLevel', { defaultMessage: 'Log level' }),
      render: (value: PolicyLogLevel) => <EuiBadge>{value}</EuiBadge>,
    },
    {
      name: i18n.translate('xdrManager.policyColumn.protection', { defaultMessage: 'Protection controls' }),
      render: (policy: XdrPolicy) => {
        const enabledFeatures = [
          policy.malwareProtection ? 'Malware' : null,
          policy.fileIntegrityMonitoring ? 'FIM' : null,
          policy.osqueryEnabled ? 'Osquery' : null,
          policy.autoUpgrade ? 'Auto upgrade' : null,
        ].filter(Boolean);

        return enabledFeatures.length > 0 ? enabledFeatures.join(', ') : 'None';
      },
    },
    {
      name: i18n.translate('xdrManager.policyColumn.assignedAgents', {
        defaultMessage: 'Assigned agents',
      }),
      render: (policy: XdrPolicy) => agents.filter((agent) => agent.policyId === policy.id).length,
    },
    {
      name: i18n.translate('xdrManager.policyColumn.actions', { defaultMessage: 'Actions' }),
      width: '160px',
      render: (policy: XdrPolicy) => (
        <EuiFlexGroup gutterSize="s" responsive={false}>
          <EuiFlexItem grow={false}>
            <EuiButtonEmpty size="xs" onClick={() => openEditPolicyFlyout(policy)}>
              {i18n.translate('xdrManager.policyEdit', { defaultMessage: 'Edit' })}
            </EuiButtonEmpty>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButtonEmpty size="xs" color="danger" onClick={() => deletePolicy(policy)}>
              {i18n.translate('xdrManager.policyDelete', { defaultMessage: 'Delete' })}
            </EuiButtonEmpty>
          </EuiFlexItem>
        </EuiFlexGroup>
      ),
    },
  ];

  const tokenColumns = [
    {
      field: 'token' as const,
      name: i18n.translate('xdrManager.tokenColumn.token', { defaultMessage: 'Token' }),
      render: (_token: string, item: XdrEnrollmentToken) => (
        <EuiText size="s">
          <code style={{ fontFamily: 'monospace', fontSize: '0.8em' }}>
            {item.token.length > 40 ? `${item.token.slice(0, 40)}…` : item.token}
          </code>
        </EuiText>
      ),
    },
    {
      field: 'policyName' as const,
      name: i18n.translate('xdrManager.tokenColumn.policy', { defaultMessage: 'Policy' }),
    },
    {
      field: 'status' as const,
      name: i18n.translate('xdrManager.tokenColumn.status', { defaultMessage: 'Status' }),
      render: (status: string) => (
        <EuiBadge color={status === 'consumed' ? 'success' : 'primary'}>{status}</EuiBadge>
      ),
    },
    {
      field: 'createdAt' as const,
      name: i18n.translate('xdrManager.tokenColumn.createdAt', { defaultMessage: 'Created' }),
      render: (ts: string) => new Date(ts).toLocaleString(),
    },
  ];

  const filteredAgents = useMemo(() => {
    const query = agentSearchQuery.trim().toLowerCase();
    if (!query) {
      return agents;
    }

    return agents.filter((agent) => {
      const policyName = policyNameById[agent.policyId] ?? agent.policyId;
      return [
        agent.name,
        policyName,
        agent.status,
        agent.version,
        agent.lastSeen,
        agent.tags.join(','),
      ]
        .join(' ')
        .toLowerCase()
        .includes(query);
    });
  }, [agentSearchQuery, agents, policyNameById]);

  const agentPageCount = Math.max(1, Math.ceil(filteredAgents.length / agentPageSize));

  useEffect(() => {
    if (agentPageIndex > agentPageCount - 1) {
      setAgentPageIndex(Math.max(0, agentPageCount - 1));
    }
  }, [agentPageCount, agentPageIndex]);

  const pagedAgents = useMemo(() => {
    const start = agentPageIndex * agentPageSize;
    return filteredAgents.slice(start, start + agentPageSize);
  }, [agentPageIndex, agentPageSize, filteredAgents]);

  const policyPageCount = Math.max(1, Math.ceil(policies.length / policyPageSize));

  useEffect(() => {
    if (policyPageIndex > policyPageCount - 1) {
      setPolicyPageIndex(Math.max(0, policyPageCount - 1));
    }
  }, [policyPageCount, policyPageIndex]);

  const pagedPolicies = useMemo(() => {
    const start = policyPageIndex * policyPageSize;
    return policies.slice(start, start + policyPageSize);
  }, [policyPageIndex, policyPageSize, policies]);

  const pageSizeOptions = [5, 10, 20, 50];

  const headerAction =
    activeTab === 'agents' ? (
      <EuiButton fill onClick={() => setIsEnrollFlyoutOpen(true)} key="enroll">
        {i18n.translate('xdrManager.enrollButton', { defaultMessage: 'Enroll XDR' })}
      </EuiButton>
    ) : activeTab === 'policies' ? (
      <EuiButton fill onClick={openCreatePolicyFlyout} key="createPolicy">
        {i18n.translate('xdrManager.createPolicy', { defaultMessage: 'Create policy' })}
      </EuiButton>
    ) : null;

  return (
    <Router basename={basename}>
      <EuiPage restrictWidth={1200}>
        <EuiPageBody component="main">
          <EuiPageHeader
            pageTitle={i18n.translate('xdrManager.pageTitle', { defaultMessage: 'XDR Manager' })}
            rightSideItems={headerAction ? [headerAction] : []}
          />

          <EuiCallOut
            title={i18n.translate('xdrManager.mdoTitle', {
              defaultMessage: 'MVP mode: local in-memory control plane',
            })}
            iconType="iInCircle"
          >
            <p>
              {i18n.translate('xdrManager.mvpDescription', {
                defaultMessage:
                  'This MVP focuses on policy assignment, enroll simulation, and remote control actions so you can validate workflows before integrating a real agent transport.',
              })}
            </p>
          </EuiCallOut>

          <EuiSpacer size="m" />

          <EuiTabs>
            <EuiTab onClick={() => setActiveTab('agents')} isSelected={activeTab === 'agents'}>
              {i18n.translate('xdrManager.tabAgents', { defaultMessage: 'Agents' })}
            </EuiTab>
            <EuiTab onClick={() => setActiveTab('policies')} isSelected={activeTab === 'policies'}>
              {i18n.translate('xdrManager.tabPolicies', { defaultMessage: 'Policy management' })}
            </EuiTab>
            <EuiTab onClick={() => setActiveTab('tokens')} isSelected={activeTab === 'tokens'}>
              {i18n.translate('xdrManager.tabTokens', { defaultMessage: 'Enrollment tokens' })}
            </EuiTab>
          </EuiTabs>

          <EuiSpacer size="m" />

          {activeTab === 'agents' && (
            <EuiPanel>
              <EuiFieldSearch
                value={agentSearchQuery}
                onChange={(event) => {
                  setAgentSearchQuery(event.target.value);
                  setAgentPageIndex(0);
                }}
                placeholder={i18n.translate('xdrManager.searchPlaceholder', { defaultMessage: 'Search...' })}
                fullWidth
              />

              <EuiSpacer size="m" />

              <div style={{ overflowX: 'auto', overflowY: 'auto', maxHeight: '55vh' }}>
                <div style={{ display: 'inline-block', minWidth: 1280 }}>
                  <EuiInMemoryTable
                    itemId="id"
                    items={pagedAgents}
                    columns={columns}
                    loading={isLoading}
                    pagination={false}
                    sorting={false}
                  />
                </div>
              </div>

              <EuiSpacer size="s" />

              <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" responsive={false}>
                <EuiFlexItem grow={false}>
                  <EuiFlexGroup alignItems="center" gutterSize="s" responsive={false}>
                    <EuiFlexItem grow={false}>
                      <EuiText size="s">
                        <span>
                          {i18n.translate('xdrManager.rowsPerPage', { defaultMessage: 'Rows per page' })}
                        </span>
                      </EuiText>
                    </EuiFlexItem>
                    <EuiFlexItem grow={false}>
                      <EuiSelect
                        compressed
                        value={String(agentPageSize)}
                        onChange={(event) => {
                          setAgentPageSize(Number(event.target.value));
                          setAgentPageIndex(0);
                        }}
                        options={pageSizeOptions.map((size) => ({ value: String(size), text: String(size) }))}
                      />
                    </EuiFlexItem>
                  </EuiFlexGroup>
                </EuiFlexItem>

                <EuiFlexItem grow={false}>
                  <EuiPagination
                    pageCount={agentPageCount}
                    activePage={agentPageIndex}
                    onPageClick={setAgentPageIndex}
                  />
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiPanel>
          )}

          {activeTab === 'policies' && (
            <EuiPanel>
              <EuiText size="s" color="subdued">
                <p>
                  {i18n.translate('xdrManager.policySectionDescription', {
                    defaultMessage:
                      'Define endpoint behavior profiles: protection controls, telemetry verbosity, and upgrade posture.',
                  })}
                </p>
              </EuiText>

              <EuiSpacer size="m" />

              <div style={{ overflowX: 'auto', overflowY: 'auto', maxHeight: '55vh' }}>
                <div style={{ display: 'inline-block', minWidth: 1280 }}>
                  <EuiInMemoryTable
                    itemId="id"
                    items={pagedPolicies}
                    columns={policyColumns}
                    loading={isLoading}
                    pagination={false}
                    sorting={false}
                  />
                </div>
              </div>

              <EuiSpacer size="s" />

              <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" responsive={false}>
                <EuiFlexItem grow={false}>
                  <EuiFlexGroup alignItems="center" gutterSize="s" responsive={false}>
                    <EuiFlexItem grow={false}>
                      <EuiText size="s">
                        <span>
                          {i18n.translate('xdrManager.rowsPerPage', { defaultMessage: 'Rows per page' })}
                        </span>
                      </EuiText>
                    </EuiFlexItem>
                    <EuiFlexItem grow={false}>
                      <EuiSelect
                        compressed
                        value={String(policyPageSize)}
                        onChange={(event) => {
                          setPolicyPageSize(Number(event.target.value));
                          setPolicyPageIndex(0);
                        }}
                        options={pageSizeOptions.map((size) => ({ value: String(size), text: String(size) }))}
                      />
                    </EuiFlexItem>
                  </EuiFlexGroup>
                </EuiFlexItem>

                <EuiFlexItem grow={false}>
                  <EuiPagination
                    pageCount={policyPageCount}
                    activePage={policyPageIndex}
                    onPageClick={setPolicyPageIndex}
                  />
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiPanel>
          )}

          {activeTab === 'tokens' && (
            <EuiPanel>
              <EuiText size="s" color="subdued">
                <p>
                  {i18n.translate('xdrManager.tokensSectionDescription', {
                    defaultMessage:
                      'Enrollment tokens authorise new agents to join. Only agents that enrolled with a valid token are accepted. Pending tokens have not yet been consumed by an agent.',
                  })}
                </p>
              </EuiText>

              <EuiSpacer size="m" />

              <EuiButton
                iconType="refresh"
                size="s"
                onClick={loadEnrollmentTokens}
                isLoading={isLoadingTokens}
              >
                {i18n.translate('xdrManager.tokensRefresh', { defaultMessage: 'Refresh' })}
              </EuiButton>

              <EuiSpacer size="m" />

              <div style={{ overflowX: 'auto' }}>
                <EuiInMemoryTable
                  itemId="token"
                  items={enrollmentTokensList}
                  loading={isLoadingTokens}
                  pagination={false}
                  sorting={false}
                  columns={tokenColumns}
                />
              </div>

              {enrollmentTokensList.length === 0 && !isLoadingTokens && (
                <>
                  <EuiSpacer size="m" />
                  <EuiText size="s" color="subdued" textAlign="center">
                    <p>
                      {i18n.translate('xdrManager.noTokens', {
                        defaultMessage: 'No enrollment tokens yet. Generate one from the Agents tab.',
                      })}
                    </p>
                  </EuiText>
                </>
              )}
            </EuiPanel>
          )}

          {isEnrollFlyoutOpen && (
            <EuiFlyout onClose={() => setIsEnrollFlyoutOpen(false)} ownFocus>
              <EuiFlyoutHeader hasBorder>
                <EuiTitle size="m">
                  <h2>
                    {i18n.translate('xdrManager.enrollFlyoutTitle', {
                      defaultMessage: 'Enroll new XDR',
                    })}
                  </h2>
                </EuiTitle>
                <EuiText size="s" color="subdued">
                  <p>
                    {i18n.translate('xdrManager.enrollFlyoutSubtitle', {
                      defaultMessage: 'Fleet-inspired enrollment flow with policy mapping.',
                    })}
                  </p>
                </EuiText>
              </EuiFlyoutHeader>

              <EuiFlyoutBody>
                <EuiForm component="form">
                  <EuiFormRow
                    label={i18n.translate('xdrManager.field.policy', {
                      defaultMessage: 'Policy',
                    })}
                  >
                    <EuiSelect
                      value={policyId}
                      onChange={(event) => setPolicyId(event.target.value)}
                      options={policies.map((policy) => ({
                        value: policy.id,
                        text: `${policy.name} — ${policy.description}`,
                      }))}
                    />
                  </EuiFormRow>

                  <EuiFormRow
                    label={i18n.translate('xdrManager.field.tags', {
                      defaultMessage: 'Tags (comma-separated)',
                    })}
                  >
                    <EuiFieldText
                      value={tagsText}
                      onChange={(event) => setTagsText(event.target.value)}
                      placeholder="linux,production"
                    />
                  </EuiFormRow>

                  <EuiHorizontalRule margin="m" />

                  <EuiFormRow
                    label={i18n.translate('xdrManager.field.enrollmentToken', {
                      defaultMessage: 'Enrollment token (for xdr-agent)',
                    })}
                    helpText={i18n.translate('xdrManager.field.enrollmentTokenHelp', {
                      defaultMessage:
                        'Generate a token for the selected policy, then set it as enrollment_token in xdr-agent config.',
                    })}
                  >
                    <EuiFieldText value={enrollmentToken} readOnly placeholder="Generate a token" />
                  </EuiFormRow>

                  <EuiButton
                    onClick={generateEnrollmentToken}
                    isLoading={isGeneratingEnrollmentToken}
                    iconType="key"
                  >
                    {i18n.translate('xdrManager.generateEnrollmentToken', {
                      defaultMessage: 'Generate enrollment token',
                    })}
                  </EuiButton>

                  {enrollmentToken && tokenPolicyId && (
                    <>
                      <EuiSpacer size="m" />
                      <EuiCallOut
                        title={
                          tokenValidationStatus === 'consumed'
                            ? i18n.translate('xdrManager.tokenConsumedTitle', {
                                defaultMessage: 'Agent enrolled',
                              })
                            : i18n.translate('xdrManager.tokenWaitingTitle', {
                                defaultMessage: 'Waiting for enrollment',
                              })
                        }
                        iconType={tokenValidationStatus === 'consumed' ? 'check' : 'clock'}
                        color={tokenValidationStatus === 'consumed' ? 'success' : 'primary'}
                      >
                        <EuiText size="s" color="subdued">
                          <p>
                            {tokenValidationStatus === 'consumed'
                              ? i18n.translate('xdrManager.tokenConsumedDetails', {
                                  defaultMessage: 'Enrollment completed for host {hostname}.',
                                  values: { hostname: tokenConsumedHostname || 'unknown' },
                                })
                              : i18n.translate('xdrManager.tokenWaitingDetails', {
                                  defaultMessage:
                                    'Run xdr-agent enroll with this token. Validation updates automatically.',
                                })}
                          </p>
                        </EuiText>
                        {tokenValidationStatus === 'waiting' && (
                          <>
                            <EuiSpacer size="s" />
                            <EuiLoadingSpinner size="m" />
                            <EuiSpacer size="s" />
                            <EuiButtonEmpty size="s" onClick={stopEnrollmentValidation}>
                              {i18n.translate('xdrManager.stopEnrollmentValidation', {
                                defaultMessage: 'Stop',
                              })}
                            </EuiButtonEmpty>
                          </>
                        )}
                        <EuiSpacer size="s" />
                        <EuiCodeBlock language="bash" isCopyable>
                          {`sudo xdr-agent enroll ${enrollmentToken} --config /etc/xdr-agent/config.json`}
                        </EuiCodeBlock>
                      </EuiCallOut>
                    </>
                  )}
                </EuiForm>
              </EuiFlyoutBody>

              <EuiFlyoutFooter>
                <EuiButtonEmpty onClick={() => setIsEnrollFlyoutOpen(false)}>
                  {i18n.translate('xdrManager.cancelButton', { defaultMessage: 'Cancel' })}
                </EuiButtonEmpty>
              </EuiFlyoutFooter>
            </EuiFlyout>
          )}

          {isPolicyFlyoutOpen && (
            <EuiFlyout onClose={() => setIsPolicyFlyoutOpen(false)} ownFocus>
              <EuiFlyoutHeader hasBorder>
                <EuiTitle size="m">
                  <h2>
                    {editingPolicyId
                      ? i18n.translate('xdrManager.editPolicyTitle', { defaultMessage: 'Edit policy' })
                      : i18n.translate('xdrManager.createPolicyTitle', {
                          defaultMessage: 'Create policy',
                        })}
                  </h2>
                </EuiTitle>
              </EuiFlyoutHeader>

              <EuiFlyoutBody>
                <EuiForm component="form">
                  <EuiFormRow
                    label={i18n.translate('xdrManager.policyField.name', {
                      defaultMessage: 'Policy name',
                    })}
                  >
                    <EuiFieldText
                      value={policyNameInput}
                      onChange={(event) => setPolicyNameInput(event.target.value)}
                      placeholder="Linux production baseline"
                    />
                  </EuiFormRow>

                  <EuiFormRow
                    label={i18n.translate('xdrManager.policyField.description', {
                      defaultMessage: 'Description',
                    })}
                  >
                    <EuiFieldText
                      value={policyDescriptionInput}
                      onChange={(event) => setPolicyDescriptionInput(event.target.value)}
                      placeholder="Balanced detection and telemetry for production workloads."
                    />
                  </EuiFormRow>

                  <EuiFormRow
                    label={i18n.translate('xdrManager.policyField.logLevel', {
                      defaultMessage: 'Telemetry log level',
                    })}
                  >
                    <EuiSelect
                      value={policyLogLevel}
                      onChange={(event) => setPolicyLogLevel(event.target.value as PolicyLogLevel)}
                      options={[
                        { value: 'minimal', text: 'Minimal' },
                        { value: 'standard', text: 'Standard' },
                        { value: 'verbose', text: 'Verbose' },
                      ]}
                    />
                  </EuiFormRow>

                  <EuiHorizontalRule margin="m" />

                  <EuiSwitch
                    label={i18n.translate('xdrManager.policyField.malware', {
                      defaultMessage: 'Malware prevention',
                    })}
                    checked={policyMalwareProtection}
                    onChange={(event) => setPolicyMalwareProtection(event.target.checked)}
                  />
                  <EuiSpacer size="s" />
                  <EuiSwitch
                    label={i18n.translate('xdrManager.policyField.fim', {
                      defaultMessage: 'File integrity monitoring',
                    })}
                    checked={policyFileIntegrity}
                    onChange={(event) => setPolicyFileIntegrity(event.target.checked)}
                  />
                  <EuiSpacer size="s" />
                  <EuiSwitch
                    label={i18n.translate('xdrManager.policyField.osquery', {
                      defaultMessage: 'Osquery module',
                    })}
                    checked={policyOsqueryEnabled}
                    onChange={(event) => setPolicyOsqueryEnabled(event.target.checked)}
                  />
                  <EuiSpacer size="s" />
                  <EuiSwitch
                    label={i18n.translate('xdrManager.policyField.autoUpgrade', {
                      defaultMessage: 'Auto-upgrade agents',
                    })}
                    checked={policyAutoUpgrade}
                    onChange={(event) => setPolicyAutoUpgrade(event.target.checked)}
                  />
                </EuiForm>
              </EuiFlyoutBody>

              <EuiFlyoutFooter>
                <EuiButtonEmpty onClick={() => setIsPolicyFlyoutOpen(false)}>
                  {i18n.translate('xdrManager.cancelPolicyButton', { defaultMessage: 'Cancel' })}
                </EuiButtonEmpty>
                <EuiButton fill onClick={savePolicy} isLoading={isSavingPolicy}>
                  {i18n.translate('xdrManager.savePolicyButton', { defaultMessage: 'Save policy' })}
                </EuiButton>
              </EuiFlyoutFooter>
            </EuiFlyout>
          )}
        </EuiPageBody>
      </EuiPage>
    </Router>
  );
};
