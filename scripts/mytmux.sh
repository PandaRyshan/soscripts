#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# mytmux.sh — tmux Project Workspace Manager
# ============================================================================
# Quick start:
#   cd ~/some-project && mytmux.sh           # create/attach with default template
#   cd ~/some-project && mytmux.sh ai         # same but with "ai" template
#   mytmux.sh some-project                    # re-attach by workspace name
#   mytmux.sh list                            # list all mytmux workspaces
#   mytmux.sh kill <name>                     # destroy a workspace
# ============================================================================

SCRIPT_NAME="mytmux.sh"
CONFIG_DIR="${HOME}/.config/mytmux"
GLOBAL_CONFIG="${CONFIG_DIR}/config.yaml"
GLOBAL_TEMPLATES="${CONFIG_DIR}/templates"
GLOBAL_HOOKS="${CONFIG_DIR}/hooks"
PROJECT_CONFIG=".mytmux"
SESSION_PREFIX="mytmux"

# ---------------------------------------------------------------------------
# Built-in defaults — written to ~/.config/mytmux/ on first run
# (Content is in heredoc blocks inside bootstrap_global_config below.)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Preflight — ensure required tools exist
# ---------------------------------------------------------------------------
preflight() {
    if ! command -v tmux &>/dev/null; then
        echo "ERROR: tmux is required but not installed." >&2
        echo "Install it: sudo apt install tmux   or   sudo snap install tmux" >&2
        exit 1
    fi

    if ! command -v yq &>/dev/null; then
        echo "yq (YAML processor) is required but not found." >&2
        if [[ ! -t 0 ]]; then
            echo "Non-interactive terminal — cannot prompt. Install yq manually:" >&2
            echo "  sudo snap install yq   or   sudo apt install yq" >&2
            exit 1
        fi
        read -r -p "Install yq now? [Y/n] " reply
        if [[ "$reply" =~ ^[Nn]$ ]]; then
            echo "Cannot proceed without yq. Exiting." >&2
            exit 1
        fi
        install_yq
    fi
}

install_yq() {
    if command -v snap &>/dev/null; then
        echo "Installing yq via snap..."
        sudo snap install yq && return 0
    fi

    if command -v apt-get &>/dev/null; then
        echo "Installing yq via apt..."
        sudo apt-get update -qq && sudo apt-get install -y yq && return 0
    fi

    local yq_url="https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64"
    local tmp_bin="/tmp/yq"
    echo "Downloading yq from GitHub..."
    curl -sSL "$yq_url" -o "$tmp_bin" && chmod +x "$tmp_bin"
    sudo mv "$tmp_bin" /usr/local/bin/yq
    echo "yq installed to /usr/local/bin/yq"
}

# ---------------------------------------------------------------------------
# Config — bootstrap, load, merge
#
# Directory layout:
#   ~/.config/mytmux/
#     config.yaml           ← top-level settings only (default_template, etc.)
#     templates/*.yaml      ← template definitions (sorted by filename)
#     hooks/*.yaml          ← hook scripts (sorted by filename)
#
#   .mytmux/                ← project-level overrides (same structure, optional)
#     config.yaml
#     templates/*.yaml
#     hooks/*.yaml
#
# Merge order (corrected): global config → global templates → global hooks →
#                          project config → project templates → project hooks
# ---------------------------------------------------------------------------

bootstrap_global_config() {
    # Top-level config.yaml
    if [[ ! -f "$GLOBAL_CONFIG" ]]; then
        mkdir -p "$CONFIG_DIR"
        echo "Bootstrapping: $GLOBAL_CONFIG"
        cat > "$GLOBAL_CONFIG" <<'YAML'
# mytmux global settings
default_template: ai
default_window_name: main
hooks_enabled: false
YAML
    fi

    # Default templates
    if [[ ! -d "$GLOBAL_TEMPLATES" ]]; then
        mkdir -p "$GLOBAL_TEMPLATES"
    fi
    if [[ ! -f "$GLOBAL_TEMPLATES/default.yaml" ]]; then
        echo "Bootstrapping: $GLOBAL_TEMPLATES/default.yaml"
        cat > "$GLOBAL_TEMPLATES/default.yaml" <<'TMPL'
# mytmux built-in templates
templates:
  ai:
    windows:
      - name: main
        panes:
          - cmd: ""                # 65% height (shrunk by pane 2's size)
          - cmd: ""                # 35% → split 55/45
            split: v               # below pane 0
            size: 15               # shrink pane 0 by 15 cells
          - cmd: "htop"
            split: h               # right of pane 1
            size: 5                # shrink pane 1 by 5 cells

  default:
    windows:
      - name: main
        panes:
          - cmd: ""
TMPL
    fi

    # Default hooks
    if [[ ! -d "$GLOBAL_HOOKS" ]]; then
        mkdir -p "$GLOBAL_HOOKS"
    fi
    if [[ ! -f "$GLOBAL_HOOKS/default.yaml" ]]; then
        echo "Bootstrapping: $GLOBAL_HOOKS/default.yaml"
        cat > "$GLOBAL_HOOKS/default.yaml" <<'HKS'
# mytmux built-in hooks
hooks:
  pre_create: |
    echo "[mytmux] Creating workspace: $MYTMUX_SESSION"
  post_create: |
    tmux send-keys -t "$MYTMUX_SESSION:0.0" "echo '=== mytmux workspace ready ==='" C-m
    tmux send-keys -t "$MYTMUX_SESSION:0.0" "echo '  Workspace : $MYTMUX_WORKSPACE'" C-m
    tmux send-keys -t "$MYTMUX_SESSION:0.0" "echo '  Template  : $MYTMUX_TEMPLATE'" C-m
    tmux send-keys -t "$MYTMUX_SESSION:0.0" "echo '  Directory : $MYTMUX_PROJECT_DIR'" C-m
    tmux send-keys -t "$MYTMUX_SESSION:0.0" "echo ''" C-m
  pre_destroy: |
    echo "[mytmux] Destroying workspace: $MYTMUX_SESSION"
HKS
    fi
}

# Merge a YAML file into a YAML string, returning the merged string
_yq_merge_file() {
    local base="$1" file="$2"
    local tmp_base tmp_out
    tmp_base=$(mktemp)
    tmp_out=$(mktemp)
    echo "$base" > "$tmp_base"
    yq eval-all 'select(fileIndex==0) * select(fileIndex==1)' "$tmp_base" "$file" > "$tmp_out" 2>/dev/null || {
        cat "$tmp_base"
        rm -f "$tmp_base" "$tmp_out"
        return
    }
    cat "$tmp_out"
    rm -f "$tmp_base" "$tmp_out"
}

# Merge all *.yaml files from a directory into a YAML string
_yq_merge_dir() {
    local base="$1" dir="$2"
    if [[ ! -d "$dir" ]]; then
        echo "$base"
        return
    fi
    local merged="$base"
    local files=()
    while IFS= read -r -d '' f; do
        files+=("$f")
    done < <(find "$dir" -maxdepth 1 -name '*.yaml' -print0 2>/dev/null | sort -z)
    for f in "${files[@]}"; do
        merged=$(_yq_merge_file "$merged" "$f")
    done
    echo "$merged"
}

load_config() {
    bootstrap_global_config

    # 1. Start with global config
    local merged
    merged=$(cat "$GLOBAL_CONFIG")

    # 2. Merge global templates and hooks BEFORE project config
    merged=$(_yq_merge_dir "$merged" "$GLOBAL_TEMPLATES")
    merged=$(_yq_merge_dir "$merged" "$GLOBAL_HOOKS")

    # 3. Merge project config.yaml (can override global templates/hooks)
    if [[ -f "${PROJECT_CONFIG}/config.yaml" ]]; then
        merged=$(_yq_merge_file "$merged" "${PROJECT_CONFIG}/config.yaml")
    fi

    # 4. Merge project templates and hooks (highest priority)
    merged=$(_yq_merge_dir "$merged" "${PROJECT_CONFIG}/templates")
    merged=$(_yq_merge_dir "$merged" "${PROJECT_CONFIG}/hooks")

    echo "$merged"
}

# ---------------------------------------------------------------------------
# Hook runner — safe eval of hook scripts
# ---------------------------------------------------------------------------
run_hook() {
    local hook_name="$1"        # pre_create | post_create | pre_destroy

    # Check hooks_enabled flag (default: false)
    local enabled
    enabled=$(yq -r '.hooks_enabled // false' <<<"$MERGED_CONFIG" 2>/dev/null)
    if [[ "$enabled" != "true" ]]; then
        return 0
    fi

    local hook_script
    hook_script=$(yq -r ".hooks.${hook_name} // \"\"" <<<"$MERGED_CONFIG" 2>/dev/null)
    if [[ -n "$hook_script" && "$hook_script" != "null" ]]; then
        echo "[mytmux] Running hook: $hook_name"
        eval "$hook_script"
    fi
}

# ---------------------------------------------------------------------------
# Template helpers
# ---------------------------------------------------------------------------
resolve_template() {
    local template_name="${1:-}"
    if [[ -z "$template_name" ]]; then
        template_name=$(yq -r '.default_template // "ai"' <<<"$MERGED_CONFIG")
    fi
    # Verify template exists
    if ! yq -e ".templates.${template_name}" <<<"$MERGED_CONFIG" &>/dev/null; then
        local available
        available=$(yq -r '.templates | keys | join(", ")' <<<"$MERGED_CONFIG")
        echo "ERROR: Template '${template_name}' not found. Available: ${available}" >&2
        exit 1
    fi
    echo "$template_name"
}

get_window_count() {
    local tpl="$1"
    yq -r ".templates.${tpl}.windows | length" <<<"$MERGED_CONFIG"
}

get_pane_count() {
    local tpl="$1" win_idx="$2"
    yq -r ".templates.${tpl}.windows[${win_idx}].panes | length" <<<"$MERGED_CONFIG"
}

get_window_name() {
    local tpl="$1" win_idx="$2"
    yq -r ".templates.${tpl}.windows[${win_idx}].name // \"main\"" <<<"$MERGED_CONFIG"
}

get_pane_cmd() {
    local tpl="$1" win_idx="$2" pane_idx="$3"
    yq -r ".templates.${tpl}.windows[${win_idx}].panes[${pane_idx}].cmd // \"\"" <<<"$MERGED_CONFIG"
}

get_pane_split() {
    local tpl="$1" win_idx="$2" pane_idx="$3"
    local split
    split=$(yq -r ".templates.${tpl}.windows[${win_idx}].panes[${pane_idx}].split // \"\"" <<<"$MERGED_CONFIG")
    if [[ -z "$split" || "$split" == "null" ]]; then
        # Default: pane 1 = v (below), pane 2 = h (right), alternating
        if (( pane_idx % 2 == 1 )); then echo "v"; else echo "h"; fi
    else
        echo "$split"
    fi
}

get_pane_size() {
    local tpl="$1" win_idx="$2" pane_idx="$3"
    yq -r ".templates.${tpl}.windows[${win_idx}].panes[${pane_idx}].size // 0" <<<"$MERGED_CONFIG"
}

# ---------------------------------------------------------------------------
# Session create / attach
# ---------------------------------------------------------------------------
create_workspace() {
    local session="$1" template="$2"

    run_hook "pre_create" || {
        echo "ERROR: pre_create hook failed (exit $?)" >&2
        exit 1
    }

    local window_count
    window_count=$(get_window_count "$template")

    if [[ "$window_count" -lt 1 ]]; then
        echo "ERROR: Template '$template' has no windows defined." >&2
        exit 1
    fi

    for ((w=0; w<window_count; w++)); do
        local wname pane_count
        wname=$(get_window_name "$template" "$w")
        pane_count=$(get_pane_count "$template" "$w")

        if [[ $w -eq 0 ]]; then
            # First window: create session itself
            local first_cmd
            first_cmd=$(get_pane_cmd "$template" 0 0)
            tmux new-session -d -s "$session" -n "$wname"
        else
            tmux new-window -t "$session" -n "$wname"
        fi

        # Create panes within this window
        for ((p=0; p<pane_count; p++)); do
            local cmd split_dir sz pane_target previous_pane
            cmd=$(get_pane_cmd "$template" "$w" "$p")
            pane_target="${session}:${w}.${p}"

            if [[ $p -gt 0 ]]; then
                split_dir=$(get_pane_split "$template" "$w" "$p")
                previous_pane="${session}:${w}.$((p-1))"

                if [[ "$split_dir" == "v" ]]; then
                    tmux split-window -v -t "${session}:${w}"
                else
                    tmux split-window -h -t "${session}:${w}"
                fi

                # Apply size: shrink the PREVIOUS pane by N cells
                sz=$(get_pane_size "$template" "$w" "$p")
                if [[ "$sz" -gt 0 ]]; then
                    if [[ "$split_dir" == "v" ]]; then
                        # Shrink previous pane (above) by moving its bottom edge up
                        if ! tmux resize-pane -t "$previous_pane" -U "$sz" 2>/dev/null; then
                            echo "WARN: Failed to resize pane $previous_pane by $sz cells" >&2
                        fi
                    else
                        # Shrink previous pane (left) by moving its right edge left
                        if ! tmux resize-pane -t "$previous_pane" -L "$sz" 2>/dev/null; then
                            echo "WARN: Failed to resize pane $previous_pane by $sz cells" >&2
                        fi
                    fi
                fi
            fi

            # Send startup command if defined
            if [[ -n "$cmd" ]]; then
                tmux send-keys -t "$pane_target" "$cmd" C-m
            fi
        done
    done

    run_hook "post_create"

    # Focus first window, first pane
    tmux select-window -t "${session}:0"
    tmux select-pane -t "${session}:0.0"
}

attach_or_create() {
    local workspace="$1" template_name="$2"

    # Sanitize workspace name
    workspace=$(echo "$workspace" | sed 's#[/. ]#-#g')
    local session="${SESSION_PREFIX}-${workspace}"

    # Load config once, store in global
    MERGED_CONFIG=$(load_config)

    # Resolve template
    template_name=$(resolve_template "$template_name")

    # Export environment for hooks
    export MYTMUX_SESSION="$session"
    export MYTMUX_WORKSPACE="$workspace"
    export MYTMUX_PROJECT_DIR="$PWD"
    export MYTMUX_TEMPLATE="$template_name"

    # Session exists? Attach. Otherwise, create.
    if tmux has-session -t "$session" 2>/dev/null; then
        echo "[mytmux] Attaching to existing workspace: $workspace (session: $session)"
        tmux attach -t "$session"
    else
        echo "[mytmux] Creating new workspace: $workspace (session: $session, template: $template_name)"
        create_workspace "$session" "$template_name"
        tmux attach -t "$session"
    fi
}

# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------
cmd_new() {
    local workspace="$1" template_name="${2:-}"

    workspace=$(echo "$workspace" | sed 's#[/. ]#-#g')
    local session="${SESSION_PREFIX}-${workspace}"

    MERGED_CONFIG=$(load_config)
    template_name=$(resolve_template "$template_name")

    export MYTMUX_SESSION="$session"
    export MYTMUX_WORKSPACE="$workspace"
    export MYTMUX_PROJECT_DIR="$PWD"
    export MYTMUX_TEMPLATE="$template_name"

    # Kill existing if present
    if tmux has-session -t "$session" 2>/dev/null; then
        echo "[mytmux] Killing existing session: $session"
        run_hook "pre_destroy" || {
            echo "ERROR: pre_destroy hook failed (exit $?). Aborting." >&2
            exit 1
        }
        tmux kill-session -t "$session"
    fi

    echo "[mytmux] Force-creating workspace: $workspace (session: $session, template: $template_name)"
    create_workspace "$session" "$template_name"
    tmux attach -t "$session"
}

cmd_list() {
    tmux list-sessions -F '#{session_name} #{session_windows} #{?session_attached,attached,detached}' 2>/dev/null \
        | grep "^${SESSION_PREFIX}-" \
        | while read -r name windows attached; do
            local ws="${name#${SESSION_PREFIX}-}"
            printf "  %-30s  windows: %s  [%s]\n" "$ws" "$windows" "$attached"
          done \
        || echo "  (no mytmux workspaces running)"
}

cmd_kill() {
    local workspace="$1"
    workspace=$(echo "$workspace" | sed 's#[/. ]#-#g')
    local session="${SESSION_PREFIX}-${workspace}"

    if ! tmux has-session -t "$session" 2>/dev/null; then
        echo "ERROR: Workspace '$workspace' not found." >&2
        exit 1
    fi

    MERGED_CONFIG=$(load_config)
    export MYTMUX_SESSION="$session"
    export MYTMUX_WORKSPACE="$workspace"
    export MYTMUX_PROJECT_DIR=""
    export MYTMUX_TEMPLATE=""

    run_hook "pre_destroy" || {
        echo "ERROR: pre_destroy hook returned non-zero. Aborting destroy." >&2
        exit 1
    }

    tmux kill-session -t "$session"
    echo "[mytmux] Workspace '$workspace' destroyed."
}

cmd_edit() {
    if [[ -d "${PROJECT_CONFIG}" ]]; then
        ${EDITOR:-vim} "${PROJECT_CONFIG}/config.yaml"
    else
        ${EDITOR:-vim} "$GLOBAL_CONFIG"
    fi
}

cmd_templates() {
    MERGED_CONFIG=$(load_config)
    local default_tpl
    default_tpl=$(yq -r '.default_template // "ai"' <<<"$MERGED_CONFIG")
    echo "Available templates (default: $default_tpl):"
    echo
    while IFS='|' read -r name desc pane_count; do
        local marker=""
        [[ "$name" == "$default_tpl" ]] && marker=" ← default"
        if [[ -n "$desc" ]]; then
            printf "  %-20s  %s  %s\n" "$name$marker" "$desc" "(${pane_count} pane(s))"
        else
            printf "  %-20s  %s\n" "$name$marker" "(${pane_count} pane(s))"
        fi
    done < <(yq -r '.templates | to_entries[] | [.key, (.value.description // ""), ((.value.windows // []) | if length > 0 then .[0].panes | length else 0 end)] | join("|")' <<<"$MERGED_CONFIG")
}

cmd_help() {
    cat <<'EOF'
mytmux.sh — tmux Project Workspace Manager

USAGE:
  mytmux.sh                           Smart mode: create/attach workspace named after current dir
  mytmux.sh <workspace>               Auto-create (default template) or attach if exists
  mytmux.sh <workspace> <template>    Create with specific template, or attach if exists
  mytmux.sh --template <tmpl>          Use named template with current-dir workspace
  mytmux.sh new <workspace> [tmpl]    Force-create (destroys existing session)
  mytmux.sh list                       List all mytmux workspaces
  mytmux.sh kill <workspace>           Destroy a workspace
   mytmux.sh edit                        Edit config (project .mytmux/ or global)
  mytmux.sh templates                  List available templates
  mytmux.sh help                       Show this help

OPTIONS:
  -t, --template <name>   Template to use when creating a new workspace.
                          Ignored if the workspace already exists (attach takes priority).

CONFIG:
  Global:     ~/.config/mytmux/
               ├── config.yaml          (top-level settings)
               ├── templates/*.yaml     (template definitions)
               └── hooks/*.yaml         (lifecycle hook scripts)

  Project:    .mytmux/                (same structure, overrides global)

EXAMPLES:
  mytmux.sh                           # workspace = current dir, default template
  mytmux.sh --template ai             # workspace = current dir, template "ai"
  mytmux.sh -t ai                     # same, short form
  mytmux.sh myproject                 # attach or create "mytmux-myproject"
  mytmux.sh myproject fullstack       # create with "fullstack" template
  mytmux.sh myproject --template ai   # same as above, --template wins over positional
  mytmux.sh new myproject             # force-recreate myproject
EOF
}

# ---------------------------------------------------------------------------
# Argument parsing — extract --template/-t, leave positional args intact
# ---------------------------------------------------------------------------
parse_args() {
    FLAG_TEMPLATE=""
    POSITIONAL=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --template|-t)
                if [[ -z "${2:-}" ]]; then
                    echo "ERROR: --template requires a value." >&2
                    exit 1
                fi
                FLAG_TEMPLATE="$2"
                shift 2
                ;;
            --template=*)
                FLAG_TEMPLATE="${1#*=}"
                shift
                ;;
            -t=*)
                FLAG_TEMPLATE="${1#*=}"
                shift
                ;;
            *)
                POSITIONAL+=("$1")
                shift
                ;;
        esac
    done

    ARG1="${POSITIONAL[0]:-}"
    ARG2="${POSITIONAL[1]:-}"
    ARG3="${POSITIONAL[2]:-}"
}

# ---------------------------------------------------------------------------
# Main — CLI dispatch
# ---------------------------------------------------------------------------
main() {
    preflight

    parse_args "$@"

    case "$ARG1" in
        new)
            [[ -z "$ARG2" ]] && { echo "ERROR: 'new' requires a workspace name." >&2; exit 1; }
            cmd_new "$ARG2" "${FLAG_TEMPLATE:-${ARG3:-}}"
            ;;
        list)
            echo "mytmux workspaces:"
            cmd_list
            ;;
        kill)
            [[ -z "$ARG2" ]] && { echo "ERROR: 'kill' requires a workspace name." >&2; exit 1; }
            cmd_kill "$ARG2"
            ;;
        edit)
            cmd_edit "${ARG2:-}"
            ;;
        templates)
            cmd_templates
            ;;
        help|-h|--help)
            cmd_help
            ;;
        "")
            # No args: workspace = current dir name, template = --template flag or default
            local ws
            ws=$(basename "$PWD")
            [[ "$ws" == "/" ]] && { echo "ERROR: Cannot create workspace at filesystem root." >&2; exit 1; }
            attach_or_create "$ws" "${FLAG_TEMPLATE:-}"
            ;;
        *)
            # Smart mode: ARG1 = workspace, ARG2 = positional template (if no --template)
            # --template flag takes precedence over positional ARG2
            attach_or_create "$ARG1" "${FLAG_TEMPLATE:-${ARG2:-}}"
            ;;
    esac
}

main "$@"
