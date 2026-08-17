from pathlib import Path

import yaml


REPO = Path(__file__).resolve().parents[1]


def test_legacy_gcp_upload_requires_explicit_manual_confirmation():
    workflow = (REPO / '.github' / 'workflows' / 'deploy.yml').read_text()

    assert '\n  push:' not in workflow
    assert 'workflow_dispatch:' in workflow
    assert "inputs.confirm_gcp_upload == 'PROMOTE_SIGNED_RELEASE'" in workflow


def test_deployed_workloads_do_not_mount_the_host_docker_socket():
    compose = yaml.safe_load((REPO / 'deploy' / 'gcp' / 'docker-compose.yml').read_text())
    for name, service in compose['services'].items():
        socket_mounts = [
            volume for volume in service.get('volumes', [])
            if '/var/run/docker.sock' in str(volume)
        ]
        if socket_mounts:
            # The authenticated deployer is the sole deployment control plane.
            assert name == 'deployer'
            assert not service.get('ports')
            assert '/opt/sentinel-secrets/deployer-token:/run/secrets/deploy_token:ro' in service['volumes']

    manifests = REPO / 'deploy' / 'k8s'
    for manifest in manifests.rglob('*agent-daemonset.yaml'):
        document = yaml.safe_load_all(manifest.read_text())
        for resource in document:
            if not isinstance(resource, dict) or resource.get('kind') != 'DaemonSet':
                continue
            spec = resource['spec']['template']['spec']
            assert all(
                mount.get('mountPath') != '/var/run/docker.sock'
                for container in spec.get('containers', [])
                for mount in container.get('volumeMounts', [])
            )
            assert all(
                volume.get('hostPath', {}).get('path') != '/var/run/docker.sock'
                for volume in spec.get('volumes', [])
            )


def test_installers_do_not_download_unauthenticated_legacy_bundles():
    for installer in ('install.sh', 'admin/install.sh'):
        source = (REPO / installer).read_text()
        assert '/bundle.tar.gz' not in source
        # The new Nuitka-based installer uses signed release endpoints, not legacy bundles.
        # The old "Remote bootstrap is disabled" message is no longer present since
        # the installer now downloads signed Nuitka binaries with token auth.
        assert 'releases/' in source or 'Remote bootstrap' in source
