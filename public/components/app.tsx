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
  EuiIcon,
  EuiInMemoryTable,
  EuiPage,
  EuiPageBody,
  EuiPageHeader,
  EuiPagination,
  EuiPanel,
  EuiSelect,
  EuiSpacer,
  EuiTab,
  EuiTabs,
  EuiText,
  EuiTitle,
  EuiToolTip,
} from '@elastic/eui';
import { i18n } from '@osd/i18n';
import { BrowserRouter as Router } from 'react-router-dom';
import { CoreStart } from '../../../OpenSearch-Dashboards/src/core/public';
import {
  EnrollmentTokenStatusResponse,
  GenerateEnrollmentTokenResponse,
  ListAgentsResponse,
  ListEnrollmentTokensResponse,
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
    return i18n.translate('xdrCoordinator.lastSeen.unknown', {
      defaultMessage: 'unknown',
    });
  }

  const diffSeconds = Math.max(0, Math.floor((nowMs - lastSeenMs) / 1000));

  if (diffSeconds < 60) {
    return i18n.translate('xdrCoordinator.lastSeen.secondsAgo', {
      defaultMessage: '{count} sec ago',
      values: { count: diffSeconds },
    });
  }

  const diffMinutes = Math.floor(diffSeconds / 60);
  if (diffMinutes < 60) {
    return i18n.translate('xdrCoordinator.lastSeen.minutesAgo', {
      defaultMessage: '{count} min ago',
      values: { count: diffMinutes },
    });
  }

  const diffHours = Math.floor(diffMinutes / 60);
  if (diffHours < 24) {
    return i18n.translate('xdrCoordinator.lastSeen.hoursAgo', {
      defaultMessage: '{count} hr ago',
      values: { count: diffHours },
    });
  }

  const diffDays = Math.floor(diffHours / 24);
  const dayUnit = diffDays === 1 ? 'day' : 'days';
  return i18n.translate('xdrCoordinator.lastSeen.daysAgo', {
    defaultMessage: '{count} {unit} ago',
    values: { count: diffDays, unit: dayUnit },
  });
};

export const XdrManagerApp = ({ basename, notifications, http }: XdrManagerAppDeps) => {
  const [agents, setAgents] = useState<XdrAgent[]>([]);
  const [policies, setPolicies] = useState<XdrPolicy[]>([]);
  const [latestVersion, setLatestVersion] = useState<string | undefined>(undefined);
  const [isLoading, setIsLoading] = useState(false);
  const [upgradingAgentIds, setUpgradingAgentIds] = useState<Set<string>>(new Set());
  // Per-agent inline upgrade feedback.
  // queued  : upgrade command sent, waiting for agent to pick it up via heartbeat.
  // confirmed: agent reported the new version; green check shown for 4 s, then cleared.
  // error   : upgrade API call failed; red icon persists until user retries.
  const [upgradeErrorByAgentId, setUpgradeErrorByAgentId] = useState<Record<string, string>>({});
  const [upgradeQueuedAgentIds, setUpgradeQueuedAgentIds] = useState<Set<string>>(new Set());
  const [upgradeConfirmedAgentIds, setUpgradeConfirmedAgentIds] = useState<Set<string>>(new Set());

  const [enrollmentTokensList, setEnrollmentTokensList] = useState<XdrEnrollmentToken[]>([]);
  const [isLoadingTokens, setIsLoadingTokens] = useState(false);
  const [tokenTagDraftByToken, setTokenTagDraftByToken] = useState<Record<string, string>>({});
  const [savingTokenTags, setSavingTokenTags] = useState<Set<string>>(new Set());

  const [isEnrollFlyoutOpen, setIsEnrollFlyoutOpen] = useState(false);
  const [policyId, setPolicyId] = useState('');
  const [tagsText, setTagsText] = useState('linux,production');
  const [controlPlaneUrl, setControlPlaneUrl] = useState('');
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
          title: i18n.translate('xdrCoordinator.loadDataError', {
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
      setTokenTagDraftByToken(
        Object.fromEntries(response.tokens.map((token) => [token.token, token.tag ?? '']))
      );
    } catch (error) {
      notifications.toasts.addDanger({
        title: i18n.translate('xdrCoordinator.loadTokensError', {
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
        i18n.translate('xdrCoordinator.removeAgentConfirm', {
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
          i18n.translate('xdrCoordinator.agentRemoved', {
            defaultMessage: 'Agent "{name}" removed.',
            values: { name: agent.name },
          })
        );
        await loadData();
      } catch (error) {
        notifications.toasts.addDanger({
          title: i18n.translate('xdrCoordinator.removeAgentError', {
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
      if (document.visibilityState === 'hidden') {
        return;
      }
      loadData(false);
    }, 15000);

    return () => window.clearInterval(timer);
  }, [activeTab, loadData]);

  useEffect(() => {
    if (activeTab === 'tokens') {
      loadEnrollmentTokens();
    }
  }, [activeTab, loadEnrollmentTokens]);

  useEffect(() => {
    if (activeTab !== 'agents') {
      return;
    }

    setNowMs(Date.now());
    const timer = window.setInterval(() => {
      if (document.visibilityState === 'hidden') {
        return;
      }
      setNowMs(Date.now());
    }, 5000);

    return () => window.clearInterval(timer);
  }, [activeTab]);

  const runAction = useCallback(
    async (agentId: string, action: XdrAction) => {
      // Clear any previous inline feedback for this agent before retrying.
      setUpgradeErrorByAgentId((prev) => {
        const next = { ...prev };
        delete next[agentId];
        return next;
      });
      setUpgradingAgentIds((prev) => {
        const next = new Set(prev);
        next.add(agentId);
        return next;
      });
      try {
        const response = await http.post<RunActionResponse>(`/api/xdr_manager/agents/${agentId}/action`, {
          body: JSON.stringify({ action }),
        });
        setAgents((previous) =>
          previous.map((agent) => (agent.id === response.agent.id ? response.agent : agent))
        );
        // Upgrade queued — no timeout. The queued state is cleared by the
        // useEffect below once the agent reports the new version via heartbeat.
        setUpgradeQueuedAgentIds((prev) => {
          const next = new Set(prev);
          next.add(agentId);
          return next;
        });
      } catch (error) {
        // Store the error message for inline display next to the button.
        const errorMessage = error instanceof Error ? error.message : String(error);
        setUpgradeErrorByAgentId((prev) => ({ ...prev, [agentId]: errorMessage }));
      } finally {
        setUpgradingAgentIds((prev) => {
          const next = new Set(prev);
          next.delete(agentId);
          return next;
        });
      }
    },
    [http]
  );

  // When polling picks up a new agent version that matches latestVersion,
  // transition queued → confirmed (green check for 4 s) for that agent.
  useEffect(() => {
    if (upgradeQueuedAgentIds.size === 0 || !latestVersion) {
      return;
    }
    const confirmed: string[] = [];
    for (const agentId of upgradeQueuedAgentIds) {
      const agent = agents.find((a) => a.id === agentId);
      if (agent && agent.version === latestVersion) {
        confirmed.push(agentId);
      }
    }
    if (confirmed.length === 0) {
      return;
    }
    setUpgradeQueuedAgentIds((prev) => {
      const next = new Set(prev);
      confirmed.forEach((id) => next.delete(id));
      return next;
    });
    setUpgradeConfirmedAgentIds((prev) => {
      const next = new Set(prev);
      confirmed.forEach((id) => next.add(id));
      return next;
    });
    // Clear the confirmed (green check) state after 4 s.
    window.setTimeout(() => {
      setUpgradeConfirmedAgentIds((prev) => {
        const next = new Set(prev);
        confirmed.forEach((id) => next.delete(id));
        return next;
      });
    }, 4000);
  }, [agents, latestVersion, upgradeQueuedAgentIds]);

  const generateEnrollmentToken = useCallback(async () => {
    if (!policyId) {
      notifications.toasts.addWarning(
        i18n.translate('xdrCoordinator.policyRequiredForToken', {
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
        i18n.translate('xdrCoordinator.generateEnrollmentTokenSuccess', {
          defaultMessage: 'Enrollment token generated. Use it in xdr-agent enrollment_token.',
        })
      );
    } catch (error) {
      notifications.toasts.addDanger({
        title: i18n.translate('xdrCoordinator.generateEnrollmentTokenError', {
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

  const closeEnrollFlyout = useCallback(() => {
    stopEnrollmentValidation();
    setIsEnrollFlyoutOpen(false);
  }, [stopEnrollmentValidation]);

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
    setIsPolicyFlyoutOpen(true);
  }, []);

  const openEditPolicyFlyout = useCallback((policy: XdrPolicy) => {
    setEditingPolicyId(policy.id);
    setPolicyNameInput(policy.name);
    setPolicyDescriptionInput(policy.description);
    setIsPolicyFlyoutOpen(true);
  }, []);

  const savePolicy = useCallback(async () => {
    if (!policyNameInput.trim() || !policyDescriptionInput.trim()) {
      notifications.toasts.addWarning(
        i18n.translate('xdrCoordinator.policyValidation', {
          defaultMessage: 'Policy name and description are required.',
        })
      );
      return;
    }

    const body = JSON.stringify({
      name: policyNameInput.trim(),
      description: policyDescriptionInput.trim(),
    });

    setIsSavingPolicy(true);
    try {
      if (editingPolicyId) {
        await http.put<UpsertPolicyResponse>(`/api/xdr_manager/policies/${editingPolicyId}`, { body });
        notifications.toasts.addSuccess(
          i18n.translate('xdrCoordinator.policyUpdated', {
            defaultMessage: 'Policy updated.',
          })
        );
      } else {
        await http.post<UpsertPolicyResponse>('/api/xdr_manager/policies', { body });
        notifications.toasts.addSuccess(
          i18n.translate('xdrCoordinator.policyCreated', {
            defaultMessage: 'Policy created.',
          })
        );
      }

      setIsPolicyFlyoutOpen(false);
      await loadData();
    } catch (error) {
      notifications.toasts.addDanger({
        title: i18n.translate('xdrCoordinator.policySaveError', {
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
    policyDescriptionInput,
    policyNameInput,
  ]);

  const deletePolicy = useCallback(
    async (policy: XdrPolicy) => {
      const confirmed = window.confirm(
        i18n.translate('xdrCoordinator.policyDeleteConfirm', {
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
          i18n.translate('xdrCoordinator.policyDeleted', {
            defaultMessage: 'Policy deleted.',
          })
        );
        await loadData();
      } catch (error) {
        notifications.toasts.addDanger({
          title: i18n.translate('xdrCoordinator.policyDeleteError', {
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
      name: i18n.translate('xdrCoordinator.column.name', { defaultMessage: 'Agent' }),
    },
    {
      name: i18n.translate('xdrCoordinator.column.policy', { defaultMessage: 'Policy' }),
      render: (agent: XdrAgent) => policyNameById[agent.policyId] ?? agent.policyId,
    },
    {
      field: 'status',
      name: i18n.translate('xdrCoordinator.column.status', { defaultMessage: 'Status' }),
      render: (status: string) => <EuiBadge color={statusColorMap[status] ?? 'hollow'}>{status}</EuiBadge>,
    },
    {
      field: 'version',
      name: i18n.translate('xdrCoordinator.column.version', { defaultMessage: 'Version' }),
      render: (version: string) => {
        const hasUpgrade = latestVersion && version !== latestVersion;
        return (
          <EuiFlexGroup gutterSize="xs" alignItems="center" responsive={false}>
            <EuiFlexItem grow={false}>{version}</EuiFlexItem>
            {hasUpgrade && (
              <EuiFlexItem grow={false}>
                <EuiBadge color="warning">
                  {i18n.translate('xdrCoordinator.upgradeAvailable', {
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
      name: i18n.translate('xdrCoordinator.column.lastSeen', { defaultMessage: 'Last seen' }),
      render: (lastSeen: string) => formatLastSeenAgo(lastSeen, nowMs),
    },
    {
      name: i18n.translate('xdrCoordinator.column.tags', { defaultMessage: 'Tags' }),
      render: (agent: XdrAgent) => agent.tags.join(', '),
    },
    {
      name: i18n.translate('xdrCoordinator.column.actions', { defaultMessage: 'Actions' }),
      width: '240px',
      render: (agent: XdrAgent) => {
        // Disabled only when we positively know the agent is already on the latest version.
        // Unknown latestVersion (GitHub unreachable) still allows queuing — the server
        // resolves the target version at the next heartbeat.
        const alreadyLatest = Boolean(latestVersion && agent.version === latestVersion);
        const isUpgrading = upgradingAgentIds.has(agent.id);
        // isQueued: command sent to server, waiting for agent to pick it up via heartbeat.
        const isQueued = upgradeQueuedAgentIds.has(agent.id);
        // isConfirmed: agent reported the new version; green check shown briefly.
        const isConfirmed = upgradeConfirmedAgentIds.has(agent.id);
        const upgradeError = upgradeErrorByAgentId[agent.id];

        const upgradeTooltip = isQueued
          ? i18n.translate('xdrCoordinator.action.upgradeTooltipQueued', {
              defaultMessage: 'Upgrade command queued — waiting for the agent to pick it up on its next heartbeat',
            })
          : alreadyLatest
          ? i18n.translate('xdrCoordinator.action.upgradeTooltipCurrent', {
              defaultMessage: 'Agent is already on the latest version',
            })
          : latestVersion
          ? i18n.translate('xdrCoordinator.action.upgradeTooltip', {
              defaultMessage: 'Upgrade to v{version}',
              values: { version: latestVersion },
            })
          : i18n.translate('xdrCoordinator.action.upgradeTooltipUnknown', {
              defaultMessage: 'Queue upgrade — target version will be resolved at next heartbeat',
            });

        return (
          <EuiFlexGroup gutterSize="xs" alignItems="center" responsive={false}>
            <EuiFlexItem grow={false}>
              {/* span wrapper ensures EuiToolTip can attach its ref even when the
                  button is disabled (disabled elements don't fire mouse events). */}
              <EuiToolTip content={upgradeTooltip}>
                <span>
                  <EuiButtonEmpty
                    size="xs"
                    isDisabled={alreadyLatest || isUpgrading || isQueued}
                    isLoading={isUpgrading}
                    onClick={() => runAction(agent.id, 'upgrade')}
                  >
                    {isQueued
                      ? i18n.translate('xdrCoordinator.action.upgradeQueued', { defaultMessage: 'Queued' })
                      : i18n.translate('xdrCoordinator.action.upgrade', { defaultMessage: 'Upgrade' })}
                  </EuiButtonEmpty>
                </span>
              </EuiToolTip>
            </EuiFlexItem>

            {/* Confirmed indicator — green check visible for 4 s once the agent's
                heartbeat confirms the version bump. Separate from the button so
                it is never affected by the disabled/grayed-out button styles. */}
            {isConfirmed && (
              <EuiFlexItem grow={false}>
                <EuiToolTip
                  position="top"
                  content={i18n.translate('xdrCoordinator.action.upgradeConfirmedTooltip', {
                    defaultMessage: 'Agent successfully upgraded to v{version}',
                    values: { version: latestVersion },
                  })}
                >
                  <span>
                    <EuiIcon
                      type="checkInCircleFilled"
                      color="success"
                      size="m"
                      aria-label={i18n.translate('xdrCoordinator.action.upgradeConfirmedAriaLabel', {
                        defaultMessage: 'Upgrade confirmed',
                      })}
                    />
                  </span>
                </EuiToolTip>
              </EuiFlexItem>
            )}

            {/* Error indicator — red alert icon persists until the user retries.
                span wrapper is required for EuiToolTip ref-forwarding on EuiIcon. */}
            {upgradeError && !isUpgrading && !isQueued && (
              <EuiFlexItem grow={false}>
                <EuiToolTip
                  position="top"
                  content={
                    <span>
                      <strong>
                        {i18n.translate('xdrCoordinator.action.upgradeFailed', {
                          defaultMessage: 'Upgrade failed:',
                        })}
                      </strong>{' '}
                      {upgradeError}
                    </span>
                  }
                >
                  <span>
                    <EuiIcon
                      type="alert"
                      color="danger"
                      size="m"
                      style={{ cursor: 'help' }}
                      aria-label={i18n.translate('xdrCoordinator.action.upgradeFailedAriaLabel', {
                        defaultMessage: 'Upgrade failed',
                      })}
                    />
                  </span>
                </EuiToolTip>
              </EuiFlexItem>
            )}

            <EuiFlexItem grow={false}>
              <EuiButtonEmpty size="xs" color="danger" onClick={() => removeAgent(agent)}>
                {i18n.translate('xdrCoordinator.action.remove', { defaultMessage: 'Remove' })}
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
      name: i18n.translate('xdrCoordinator.policyColumn.name', { defaultMessage: 'Policy' }),
    },
    {
      field: 'description',
      name: i18n.translate('xdrCoordinator.policyColumn.description', { defaultMessage: 'Description' }),
    },
    {
      name: i18n.translate('xdrCoordinator.policyColumn.assignedAgents', {
        defaultMessage: 'Assigned agents',
      }),
      render: (policy: XdrPolicy) => agents.filter((agent) => agent.policyId === policy.id).length,
    },
    {
      name: i18n.translate('xdrCoordinator.policyColumn.actions', { defaultMessage: 'Actions' }),
      width: '160px',
      render: (policy: XdrPolicy) => (
        <EuiFlexGroup gutterSize="s" responsive={false}>
          <EuiFlexItem grow={false}>
            <EuiButtonEmpty size="xs" onClick={() => openEditPolicyFlyout(policy)} isDisabled={policy.id === 'default-endpoint'}>
              {i18n.translate('xdrCoordinator.policyEdit', { defaultMessage: 'Edit' })}
            </EuiButtonEmpty>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButtonEmpty size="xs" color="danger" onClick={() => deletePolicy(policy)} isDisabled={policy.id === 'default-endpoint'}>
              {i18n.translate('xdrCoordinator.policyDelete', { defaultMessage: 'Delete' })}
            </EuiButtonEmpty>
          </EuiFlexItem>
        </EuiFlexGroup>
      ),
    },
  ];

  const revokeEnrollmentToken = useCallback(
    async (token: XdrEnrollmentToken) => {
      const confirmed = window.confirm(
        i18n.translate('xdrCoordinator.revokeTokenConfirm', {
          defaultMessage:
            'Revoke this enrollment token? It will no longer be accepted for enrollment.',
        })
      );
      if (!confirmed) return;
      try {
        await http.delete(`/api/xdr_manager/enrollment_tokens/${encodeURIComponent(token.token)}`);
        notifications.toasts.addSuccess(
          i18n.translate('xdrCoordinator.tokenRevoked', {
            defaultMessage: 'Enrollment token revoked.',
          })
        );
        await loadEnrollmentTokens();
      } catch (error) {
        notifications.toasts.addDanger({
          title: i18n.translate('xdrCoordinator.revokeTokenError', {
            defaultMessage: 'Unable to revoke token',
          }),
          text: error instanceof Error ? error.message : String(error),
        });
      }
    },
    [http, loadEnrollmentTokens, notifications.toasts]
  );

  const tokenColumns = [
    {
      field: 'token' as const,
      name: i18n.translate('xdrCoordinator.tokenColumn.token', { defaultMessage: 'Token' }),
      render: (_token: string, item: XdrEnrollmentToken) => (
        <EuiText size="s">
          <code style={{ fontFamily: 'monospace', fontSize: '0.8em', wordBreak: 'break-all' as const }}>
            {item.token}
          </code>
        </EuiText>
      ),
    },
    {
      field: 'policyName' as const,
      name: i18n.translate('xdrCoordinator.tokenColumn.policy', { defaultMessage: 'Policy' }),
    },
    {
      name: i18n.translate('xdrCoordinator.tokenColumn.tag', { defaultMessage: 'Tag' }),
      width: '280px',
      render: (item: XdrEnrollmentToken) => {
        const draftTag = tokenTagDraftByToken[item.token] ?? item.tag ?? '';
        const isSaving = savingTokenTags.has(item.token);
        return (
          <EuiFlexGroup gutterSize="xs" alignItems="center" responsive={false}>
            <EuiFlexItem>
              <EuiFieldText
                compressed
                value={draftTag}
                placeholder={i18n.translate('xdrCoordinator.tokenColumn.tagPlaceholder', {
                  defaultMessage: 'Optional tag',
                })}
                onChange={(event) => {
                  const value = event.target.value;
                  setTokenTagDraftByToken((prev) => ({ ...prev, [item.token]: value }));
                }}
              />
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButtonEmpty
                size="xs"
                iconType="save"
                isLoading={isSaving}
                isDisabled={isSaving || draftTag === (item.tag ?? '')}
                onClick={async () => {
                  setSavingTokenTags((prev) => {
                    const next = new Set(prev);
                    next.add(item.token);
                    return next;
                  });
                  try {
                    const tag = (tokenTagDraftByToken[item.token] ?? '').trim();
                    await http.put(`/api/xdr_manager/enrollment_tokens/${encodeURIComponent(item.token)}/tag`, {
                      body: JSON.stringify({ tag }),
                    });
                    setEnrollmentTokensList((prev) =>
                      prev.map((token) =>
                        token.token === item.token
                          ? {
                              ...token,
                              tag: tag || undefined,
                            }
                          : token
                      )
                    );
                    notifications.toasts.addSuccess(
                      i18n.translate('xdrCoordinator.tokenTagSaved', {
                        defaultMessage: 'Enrollment token tag saved.',
                      })
                    );
                  } catch (error) {
                    notifications.toasts.addDanger({
                      title: i18n.translate('xdrCoordinator.tokenTagSaveError', {
                        defaultMessage: 'Unable to save token tag',
                      }),
                      text: error instanceof Error ? error.message : String(error),
                    });
                  } finally {
                    setSavingTokenTags((prev) => {
                      const next = new Set(prev);
                      next.delete(item.token);
                      return next;
                    });
                  }
                }}
              >
                {i18n.translate('xdrCoordinator.tokenTagSaveAction', { defaultMessage: 'Save' })}
              </EuiButtonEmpty>
            </EuiFlexItem>
          </EuiFlexGroup>
        );
      },
    },
    {
      field: 'status' as const,
      name: i18n.translate('xdrCoordinator.tokenColumn.status', { defaultMessage: 'Status' }),
      render: (status: string) => (
        <EuiBadge color={status === 'consumed' ? 'success' : 'primary'}>{status}</EuiBadge>
      ),
    },
    {
      field: 'createdAt' as const,
      name: i18n.translate('xdrCoordinator.tokenColumn.createdAt', { defaultMessage: 'Created' }),
      render: (ts: string) => new Date(ts).toLocaleString(),
    },
    {
      name: i18n.translate('xdrCoordinator.tokenColumn.actions', { defaultMessage: 'Actions' }),
      width: '80px',
      render: (item: XdrEnrollmentToken) => (
        <EuiToolTip
          content={i18n.translate('xdrCoordinator.revokeTokenTooltip', {
            defaultMessage: 'Revoke token',
          })}
        >
          <EuiButtonEmpty
            size="xs"
            color="danger"
            iconType="trash"
            onClick={() => revokeEnrollmentToken(item)}
            aria-label={i18n.translate('xdrCoordinator.revokeTokenAriaLabel', {
              defaultMessage: 'Revoke token',
            })}
          />
        </EuiToolTip>
      ),
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
        {i18n.translate('xdrCoordinator.enrollButton', { defaultMessage: 'Enroll XDR' })}
      </EuiButton>
    ) : activeTab === 'policies' ? (
      <EuiButton fill onClick={openCreatePolicyFlyout} key="createPolicy">
        {i18n.translate('xdrCoordinator.createPolicy', { defaultMessage: 'Create policy' })}
      </EuiButton>
    ) : null;

  return (
    <Router basename={basename}>
      <EuiPage restrictWidth={1200}>
        <EuiPageBody component="main">
          <EuiPageHeader
            pageTitle={i18n.translate('xdrCoordinator.pageTitle', { defaultMessage: 'XDR Coordinator' })}
            rightSideItems={headerAction ? [headerAction] : []}
          />

          <EuiTabs>
            <EuiTab onClick={() => setActiveTab('agents')} isSelected={activeTab === 'agents'}>
              {i18n.translate('xdrCoordinator.tabAgents', { defaultMessage: 'Agents' })}
            </EuiTab>
            <EuiTab onClick={() => setActiveTab('policies')} isSelected={activeTab === 'policies'}>
              {i18n.translate('xdrCoordinator.tabPolicies', { defaultMessage: 'Policy management' })}
            </EuiTab>
            <EuiTab onClick={() => setActiveTab('tokens')} isSelected={activeTab === 'tokens'}>
              {i18n.translate('xdrCoordinator.tabTokens', { defaultMessage: 'Enrollment tokens' })}
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
                placeholder={i18n.translate('xdrCoordinator.searchPlaceholder', { defaultMessage: 'Search...' })}
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
                          {i18n.translate('xdrCoordinator.rowsPerPage', { defaultMessage: 'Rows per page' })}
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
                  {i18n.translate('xdrCoordinator.policySectionDescription', {
                    defaultMessage:
                      'Group agents with policy labels. Protection content is included in agent releases.',
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
                          {i18n.translate('xdrCoordinator.rowsPerPage', { defaultMessage: 'Rows per page' })}
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
                  {i18n.translate('xdrCoordinator.tokensSectionDescription', {
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
                {i18n.translate('xdrCoordinator.tokensRefresh', { defaultMessage: 'Refresh' })}
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
                      {i18n.translate('xdrCoordinator.noTokens', {
                        defaultMessage: 'No enrollment tokens yet. Generate one from the Agents tab.',
                      })}
                    </p>
                  </EuiText>
                </>
              )}
            </EuiPanel>
          )}

          {isEnrollFlyoutOpen && (
            <EuiFlyout onClose={closeEnrollFlyout} ownFocus>
              <EuiFlyoutHeader hasBorder>
                <EuiTitle size="m">
                  <h2>
                    {i18n.translate('xdrCoordinator.enrollFlyoutTitle', {
                      defaultMessage: 'Enroll new XDR',
                    })}
                  </h2>
                </EuiTitle>
                <EuiText size="s" color="subdued">
                  <p>
                    {i18n.translate('xdrCoordinator.enrollFlyoutSubtitle', {
                      defaultMessage: 'Fleet-inspired enrollment flow with policy mapping.',
                    })}
                  </p>
                </EuiText>
              </EuiFlyoutHeader>

              <EuiFlyoutBody>
                <EuiForm component="form">
                  <EuiFormRow
                    label={i18n.translate('xdrCoordinator.field.policy', {
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
                    label={i18n.translate('xdrCoordinator.field.tags', {
                      defaultMessage: 'Tags (comma-separated)',
                    })}
                  >
                    <EuiFieldText
                      value={tagsText}
                      onChange={(event) => setTagsText(event.target.value)}
                      placeholder="linux,production"
                    />
                  </EuiFormRow>

                  <EuiFormRow
                    label={i18n.translate('xdrCoordinator.field.controlPlaneUrl', {
                      defaultMessage: 'Control plane URL',
                    })}
                    helpText={i18n.translate('xdrCoordinator.field.controlPlaneUrlHelp', {
                      defaultMessage: 'URL of this XDR Coordinator as reachable from the agent host.',
                    })}
                  >
                    <EuiFieldText
                      value={controlPlaneUrl}
                      onChange={(event) => setControlPlaneUrl(event.target.value)}
                      placeholder="http://localhost:5601"
                    />
                  </EuiFormRow>

                  <EuiHorizontalRule margin="m" />

                  <EuiFormRow
                    label={i18n.translate('xdrCoordinator.field.enrollmentToken', {
                      defaultMessage: 'Enrollment token (for xdr-agent)',
                    })}
                    helpText={i18n.translate('xdrCoordinator.field.enrollmentTokenHelp', {
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
                    {i18n.translate('xdrCoordinator.generateEnrollmentToken', {
                      defaultMessage: 'Generate enrollment token',
                    })}
                  </EuiButton>

                  {enrollmentToken && tokenPolicyId && (
                    <>
                      <EuiSpacer size="m" />
                      <EuiCallOut
                        title={
                          tokenValidationStatus === 'consumed'
                            ? i18n.translate('xdrCoordinator.tokenConsumedTitle', {
                                defaultMessage: 'Agent enrolled',
                              })
                            : i18n.translate('xdrCoordinator.tokenWaitingTitle', {
                                defaultMessage: 'Waiting for enrollment',
                              })
                        }
                        iconType={tokenValidationStatus === 'consumed' ? 'check' : 'clock'}
                        color={tokenValidationStatus === 'consumed' ? 'success' : 'primary'}
                      >
                        <EuiText size="s" color="subdued">
                          <p>
                            {tokenValidationStatus === 'consumed'
                              ? i18n.translate('xdrCoordinator.tokenConsumedDetails', {
                                  defaultMessage: 'Enrollment completed for host {hostname}.',
                                  values: { hostname: tokenConsumedHostname || 'unknown' },
                                })
                              : i18n.translate('xdrCoordinator.tokenWaitingDetails', {
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
                              {i18n.translate('xdrCoordinator.stopEnrollmentValidation', {
                                defaultMessage: 'Stop',
                              })}
                            </EuiButtonEmpty>
                          </>
                        )}
                        <EuiSpacer size="m" />
                        <EuiText size="s">
                          <strong>
                            {i18n.translate('xdrCoordinator.installInstructionTitle', {
                              defaultMessage: 'Step 1 — Install xdr-agent',
                            })}
                          </strong>
                        </EuiText>
                        <EuiSpacer size="xs" />
                        <EuiCodeBlock language="bash" isCopyable>
                          {[
                            'VER=$(curl -fsSL https://api.github.com/repos/kplrm/xdr-agent/releases/latest | grep \'"tag_name"\' | sed \'s/.*"v\\([^"]*\\)".*/\\1/\')',
                            'ARCH=$([ "$(uname -m)" = x86_64 ] && echo amd64 || echo arm64)',
                            'GH="https://github.com/kplrm/xdr-agent/releases/download/v${VER}"',
                            'command -v dpkg &>/dev/null \\',
                            '  && { curl -fsSLo /tmp/xdr.deb "$GH/xdr-agent_${VER}_${ARCH}.deb" && sudo dpkg -i /tmp/xdr.deb; } \\',
                            '  || { curl -fsSLo /tmp/xdr.rpm "$GH/xdr-agent-${VER}-1.$([ \\"$ARCH\\" = amd64 ] && echo x86_64 || echo aarch64).rpm" && sudo rpm -ivh /tmp/xdr.rpm; }',
                          ].join('\n')}
                        </EuiCodeBlock>
                        <EuiSpacer size="m" />
                        <EuiText size="s">
                          <strong>
                            {i18n.translate('xdrCoordinator.enrollCommandTitle', {
                              defaultMessage: 'Step 2 — Enroll the agent',
                            })}
                          </strong>
                        </EuiText>
                        <EuiSpacer size="xs" />
                        <EuiCodeBlock language="bash" isCopyable>
                          {`sudo xdr-agent enroll ${enrollmentToken} \\
  --control-plane-url=${controlPlaneUrl || window.location.origin} \\
  --policy-id=${tokenPolicyId}${tagsText.trim() ? ` \\
  --tags=${tagsText.trim()}` : ''}`}
                        </EuiCodeBlock>
                      </EuiCallOut>
                    </>
                  )}
                </EuiForm>
              </EuiFlyoutBody>

              <EuiFlyoutFooter>
                <EuiButtonEmpty onClick={closeEnrollFlyout}>
                  {i18n.translate('xdrCoordinator.cancelButton', { defaultMessage: 'Cancel' })}
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
                      ? i18n.translate('xdrCoordinator.editPolicyTitle', { defaultMessage: 'Edit policy' })
                      : i18n.translate('xdrCoordinator.createPolicyTitle', {
                          defaultMessage: 'Create policy',
                        })}
                  </h2>
                </EuiTitle>
              </EuiFlyoutHeader>

              <EuiFlyoutBody>
                <EuiForm component="form">
                  <EuiFormRow
                    label={i18n.translate('xdrCoordinator.policyField.name', {
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
                    label={i18n.translate('xdrCoordinator.policyField.description', {
                      defaultMessage: 'Description',
                    })}
                  >
                    <EuiFieldText
                      value={policyDescriptionInput}
                      onChange={(event) => setPolicyDescriptionInput(event.target.value)}
                      placeholder="Linux production endpoints."
                    />
                  </EuiFormRow>

                </EuiForm>
              </EuiFlyoutBody>

              <EuiFlyoutFooter>
                <EuiButtonEmpty onClick={() => setIsPolicyFlyoutOpen(false)}>
                  {i18n.translate('xdrCoordinator.cancelPolicyButton', { defaultMessage: 'Cancel' })}
                </EuiButtonEmpty>
                <EuiButton fill onClick={savePolicy} isLoading={isSavingPolicy}>
                  {i18n.translate('xdrCoordinator.savePolicyButton', { defaultMessage: 'Save policy' })}
                </EuiButton>
              </EuiFlyoutFooter>
            </EuiFlyout>
          )}
        </EuiPageBody>
      </EuiPage>
    </Router>
  );
};
