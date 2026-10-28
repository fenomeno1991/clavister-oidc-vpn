import QtQuick
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Commons as Commons
import qs.Ui

// Clavister VPN bar widget: the bar icon shows the tunnel state, the popup
// lists remembered gateways (most recently used first) and takes a new
// address. All state comes from `clavister-vpn status --json`; connect and
// disconnect open a terminal because sudo needs somewhere to ask for the
// password and the browser login prints progress there.
Panel {
  id: root
  moduleName: "io.github.fenomeno1991.clavister-vpn"
  ipcTarget: "io.github.fenomeno1991.clavister-vpn"
  // Own the IpcHandler so it can also expose connect/disconnect
  // (e.g. `omarchy-shell io.github.fenomeno1991.clavister-vpn up vpn.example.com`).
  manageIpc: false

  property string vpnState: "disconnected"  // "connected" | "connecting" | "disconnected"
  property string activeServer: ""
  property string lastServer: ""
  property var servers: []
  // Set when a connect is started from here so the row reads "Connecting…"
  // before the CLI process shows up in the next status poll.
  property string pendingServer: ""
  property string addressText: ""

  // Cursor over the gateway rows; index servers.length is the address field.
  property bool cursorActive: false
  property int selectedIndex: -1

  readonly property bool connected: vpnState === "connected"
  readonly property bool connecting: vpnState === "connecting" || pendingServer !== ""
  readonly property string icon: connected ? "󰌋" : "󰌆"
  readonly property color dim: Qt.darker(barForeground, 1.4)
  readonly property color hoverFill: bar ? Style.hoverFillFor(bar.foreground, Commons.Color.accent) : "transparent"
  readonly property color selectedFill: bar ? Style.selectedFillFor(bar.foreground, Commons.Color.accent) : "transparent"

  readonly property string heroMeta: {
    if (connected) return "Connected" + (activeServer ? " · " + activeServer : "")
    if (connecting) return "Connecting" + (pendingServer ? " · " + pendingServer : "…")
    return "Disconnected"
  }

  function cli(args) {
    // Login shell so ~/.local/bin is on PATH; args stay separate argv entries.
    return ["bash", "-lc", 'exec clavister-vpn "$@"', "clavister-vpn"].concat(args)
  }

  function refresh() {
    if (!statusProc.running) statusProc.running = true
  }

  function updateStatus(raw) {
    var data
    try { data = JSON.parse(String(raw || "")) } catch (e) { return }
    vpnState = data.state || "disconnected"
    activeServer = data.server || ""
    lastServer = data.last_server || ""
    servers = data.servers || []
    if (vpnState !== "disconnected") pendingServer = ""
    if (selectedIndex > servers.length) selectedIndex = servers.length
  }

  function run(args) {
    if (actionProc.running) return
    actionProc.command = cli(args)
    actionProc.running = true
  }

  // Anything that opens a window must be detached from the shell: a terminal
  // started under a Process never shows up.
  function launch(args) {
    console.log("clavister-vpn: launching", JSON.stringify(cli(args)))
    Quickshell.execDetached(cli(args))
  }

  function connectTo(server) {
    server = String(server || "").trim()
    if (server === "") return
    pendingServer = server
    pendingTimer.restart()
    launch(["connect", "--terminal", server])
    close()
  }

  function disconnect() {
    launch(["disconnect", "--terminal"])
    close()
  }

  function forget(server) {
    run(["forget", server])
  }

  function toggleConnection() {
    if (connected || connecting) disconnect()
    else if (lastServer) connectTo(lastServer)
    else focusAddress()
  }

  function activateRow(server) {
    if (connected && server === activeServer) disconnect()
    else connectTo(server)
  }

  function submitAddress() {
    if (addressText.trim() === "") return
    var server = addressText
    addressText = ""
    connectTo(server)
  }

  function focusAddress() {
    cursorActive = true
    selectedIndex = servers.length
    addressField.forceActiveFocus()
  }

  function moveCursor(dy) {
    if (!cursorActive) {
      cursorActive = true
      selectedIndex = dy < 0 ? servers.length : 0
    } else {
      selectedIndex = Math.max(0, Math.min(servers.length, selectedIndex + dy))
    }
    if (selectedIndex === servers.length) addressField.forceActiveFocus()
  }

  onOpenedChanged: {
    if (opened) {
      refresh()
      cursorActive = false
      selectedIndex = -1
      addressText = ""
    }
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  IpcHandler {
    target: root.ipcTarget

    function open(): void { root.open() }
    function close(): void { root.close() }
    function show(): void { root.open() }
    function hide(): void { root.close() }
    function toggle(): void { root.toggle() }
    // Not connect/disconnect: those names are taken by QObject itself
    function up(server: string): void { root.connectTo(server || root.lastServer) }
    function down(): void { root.disconnect() }
  }

  Process {
    id: statusProc
    command: root.cli(["status", "--json"])
    stdout: StdioCollector { waitForEnd: true; onStreamFinished: root.updateStatus(text) }
  }

  Process {
    id: actionProc
    onExited: root.refresh()
  }

  Timer {
    interval: root.opened || root.connecting ? 1500 : 3000
    running: true
    repeat: true
    triggeredOnStart: true
    onTriggered: root.refresh()
  }

  // Gives up on the optimistic state if the terminal was closed before the
  // CLI got going (e.g. sudo cancelled).
  Timer {
    id: pendingTimer
    interval: 15000
    onTriggered: root.pendingServer = ""
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: root.icon
    tooltipText: ""
    onPressed: function(b) { root.toggle() }

    SequentialAnimation on opacity {
      running: root.connecting
      loops: Animation.Infinite
      alwaysRunToEnd: true
      NumberAnimation { from: 1.0; to: 0.4; duration: 700; easing.type: Easing.InOutSine }
      NumberAnimation { from: 0.4; to: 1.0; duration: 700; easing.type: Easing.InOutSine }
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(340))
    contentHeight: panel.fittedContentHeight(column.implicitHeight)

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onMoveRequested: function(dx, dy) { if (dy !== 0) root.moveCursor(dy) }
      onActivateRequested: {
        if (root.cursorActive && root.selectedIndex >= 0 && root.selectedIndex < root.servers.length)
          root.activateRow(root.servers[root.selectedIndex])
      }
      onDeleteRequested: {
        if (root.cursorActive && root.selectedIndex >= 0 && root.selectedIndex < root.servers.length)
          root.forget(root.servers[root.selectedIndex])
      }
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onTextKey: function(t) {
        if (t === "a" || t === "A") root.focusAddress()
        else if (t === "r" || t === "R") root.refresh()
      }

      Column {
        id: column
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        spacing: Style.space(12)

        // ---------- Hero: VPN icon · state · on/off ----------
        Item {
          width: parent.width
          implicitHeight: Math.max(heroIcon.implicitHeight, heroLabels.implicitHeight, powerSwitch.implicitHeight)

          Text {
            id: heroIcon
            textFormat: Text.PlainText
            text: root.icon
            color: root.bar.foreground
            font.family: root.bar.fontFamily
            font.pixelSize: Style.font.display
            opacity: root.connected ? 1.0 : 0.5
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
          }

          ToggleSwitch {
            id: powerSwitch
            checked: root.connected || root.connecting
            foreground: root.bar.foreground
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            onToggled: root.toggleConnection()

            PanelToolTip {
              visible: powerSwitch.containsMouse
              text: root.connected || root.connecting ? "Disconnect"
                : (root.lastServer ? "Connect to " + root.lastServer : "Add a gateway below")
              fontFamily: root.bar.fontFamily
            }
          }

          Column {
            id: heroLabels
            anchors.left: heroIcon.right
            anchors.leftMargin: Style.space(14)
            anchors.right: powerSwitch.left
            anchors.rightMargin: Style.space(12)
            anchors.verticalCenter: parent.verticalCenter
            spacing: Style.space(2)

            Text {
              textFormat: Text.PlainText
              text: "Clavister VPN"
              color: root.bar.foreground
              font.family: root.bar.fontFamily
              font.pixelSize: Style.font.title
              font.bold: true
              elide: Text.ElideRight
              width: parent.width
            }

            Text {
              textFormat: Text.PlainText
              text: root.heroMeta.toUpperCase()
              color: root.dim
              font.family: root.bar.fontFamily
              font.pixelSize: Style.font.caption
              font.bold: true
              font.letterSpacing: 1.2
              elide: Text.ElideRight
              width: parent.width
            }
          }
        }

        PanelSeparator {
          foreground: root.bar.foreground
        }

        // ---------- Remembered gateways ----------
        Column {
          width: parent.width
          spacing: Style.space(6)

          PanelSectionHeader {
            text: "GATEWAYS"
            foreground: root.bar.foreground
            fontFamily: root.bar.fontFamily
          }

          Text {
            visible: root.servers.length === 0
            textFormat: Text.PlainText
            text: "No gateways yet. Add one below."
            color: root.dim
            font.family: root.bar.fontFamily
            font.pixelSize: Style.font.bodySmall
          }

          Repeater {
            model: root.servers
            GatewayRow {
              required property var modelData
              required property int index
              width: parent.width
              server: String(modelData)
              rowIndex: index
            }
          }
        }

        // ---------- New address ----------
        Item {
          width: parent.width
          implicitHeight: addressField.implicitHeight

          TextField {
            id: addressField
            anchors.left: parent.left
            anchors.right: addButton.left
            anchors.rightMargin: Style.space(6)
            anchors.verticalCenter: parent.verticalCenter
            placeholderText: "Add gateway address"
            font.family: Style.font.family
            font.pixelSize: Style.font.body
            foreground: root.bar.foreground
            horizontalPadding: Style.spacing.controlGap
            verticalPadding: Style.spacing.controlPaddingY
            hasCursor: root.cursorActive && root.selectedIndex === root.servers.length && !activeFocus
            text: root.addressText

            onTextChanged: if (text !== root.addressText) root.addressText = text
            onAccepted: root.submitAddress()
            onActiveFocusChanged: if (activeFocus) { root.cursorActive = true; root.selectedIndex = root.servers.length }
            Keys.onEscapePressed: root.close()
            Keys.onUpPressed: {
              if (root.servers.length === 0) return
              root.selectedIndex = root.servers.length - 1
              keyCatcher.forceActiveFocus()
            }
          }

          PanelActionButton {
            id: addButton
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            enabled: root.addressText.trim() !== ""
            iconText: "󰄬"
            tooltipText: "Connect"
            foreground: root.bar.foreground
            fontFamily: root.bar.fontFamily
            onClicked: root.submitAddress()
          }
        }
      }
    }
  }

  component GatewayRow: CursorSurface {
    id: row
    property string server: ""
    property int rowIndex: -1

    readonly property bool isActive: root.connected && root.activeServer === server
    readonly property bool isPending: root.connecting && root.pendingServer === server
    readonly property bool isSelected: root.cursorActive && root.selectedIndex === rowIndex

    readonly property string statusText: {
      if (isActive) return "Connected"
      if (isPending) return "Connecting…"
      if (server === root.lastServer) return "Last used"
      return ""
    }

    hasCursor: isSelected
    current: isActive
    foreground: root.bar.foreground
    fill: root.hoverFill
    currentFill: root.selectedFill
    implicitHeight: rowBody.implicitHeight

    MouseArea {
      anchors.fill: parent
      hoverEnabled: true
      acceptedButtons: Qt.LeftButton
      cursorShape: Qt.PointingHandCursor
      onContainsMouseChanged: if (containsMouse) { root.cursorActive = true; root.selectedIndex = row.rowIndex }
      onClicked: root.activateRow(row.server)
    }

    Item {
      id: rowBody
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.top: parent.top
      anchors.leftMargin: Style.space(10)
      anchors.rightMargin: Style.space(10)
      implicitHeight: Math.max(rowIcon.implicitHeight, rowInfo.implicitHeight, forgetButton.implicitHeight) + Style.spacing.rowPaddingX

      Text {
        id: rowIcon
        textFormat: Text.PlainText
        text: row.isActive ? "󰌋" : "󰌆"
        color: row.isActive || row.isPending ? root.bar.foreground : Qt.darker(root.bar.foreground, 1.5)
        font.family: root.bar.fontFamily
        font.pixelSize: Style.font.title
        anchors.left: parent.left
        anchors.verticalCenter: parent.verticalCenter
      }

      Column {
        id: rowInfo
        spacing: Style.space(1)
        anchors.left: rowIcon.right
        anchors.leftMargin: Style.space(10)
        anchors.right: forgetButton.left
        anchors.rightMargin: Style.space(8)
        anchors.verticalCenter: parent.verticalCenter

        Text {
          textFormat: Text.PlainText
          text: row.server
          color: root.bar.foreground
          font.family: root.bar.fontFamily
          font.pixelSize: Style.font.body
          elide: Text.ElideRight
          width: parent.width
        }

        Text {
          textFormat: Text.PlainText
          text: row.statusText
          visible: text !== ""
          height: visible ? implicitHeight : 0
          color: row.isActive || row.isPending ? root.bar.foreground : root.dim
          font.family: root.bar.fontFamily
          font.pixelSize: Style.font.caption
          elide: Text.ElideRight
          width: parent.width
        }
      }

      // Forget only shows under the cursor, like Wi-Fi's forget network.
      PanelActionButton {
        id: forgetButton
        anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter
        opacity: row.isSelected && !row.isActive ? 1 : 0
        enabled: opacity > 0
        iconText: "󰅙"
        tooltipText: "Forget gateway"
        foreground: root.bar.foreground
        hoverColor: root.bar.urgent
        fontFamily: root.bar.fontFamily
        onClicked: root.forget(row.server)
      }
    }
  }
}
