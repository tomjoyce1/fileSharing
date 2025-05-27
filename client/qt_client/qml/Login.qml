// main.qml
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15


Item {
    visible: true
    width: 800
    height: 400

    Dialog{
        id: errorDialog
        title:"Login failed"
        modal:true
        standardButtons: Dialog.Ok
        visible:false

        contentItem: Text{
            id:errorText
            text:""
            wrapMode:Text.Wrap
            width:parent.width
        }
    }



    FontLoader {
        id: productSansRegular
        source: "qrc:/assets/product-sans/Product Sans Regular.ttf"
    }


    FontLoader {
        id: productSansBold
        source: "qrc:/assets/product-sans/Product Sans Bold.ttf"
    }

    FontLoader {
        id: productSansItalic
        source: "qrc:/assets/product-sans/Product Sans Italic.ttf"
    }

    // font.pixelSize: 16


    Rectangle{
        anchors.centerIn: parent
        width: parent.width * 0.25
        height: columnLayout.implicitHeight + 100
        // color: "gray"
                color: "#ffffff"
        radius: 12

        ColumnLayout {
            id:columnLayout
            anchors.fill:parent
            anchors.margins:20
            spacing:15

            // to hold image
            Rectangle{
                height:50
                width:parent.width
                anchors.horizontalCenter: parent.horizontalCenter


                Image {
                     source:"qrc:/assets/BLACKs.png"
                    fillMode: Image.PreserveAspectFit
                    height:50
                    anchors.centerIn:parent


                }

            }


            Label {
                text: "Sign in to Shhhare"
                font.pixelSize: 26
                font.family: productSansRegular.name
                color: "black"
                horizontalAlignment: Text.AlignHCenter
                Layout.alignment: Qt.AlignHCenter
            }



            TextField {
                id: usernameField
                placeholderText: "Username"
                Layout.fillWidth:true
                Layout.preferredHeight:40

                background:Rectangle{
                    color:"white"
                    radius:5
                    border.color:"#ccc"
                }
                padding:10

            }

            TextField {
                id: passwordField
                placeholderText: "Password"
                echoMode: TextInput.Password
                Layout.fillWidth:true
                Layout.preferredHeight:40
                background:Rectangle{
                    color:"white"
                    radius:5
                    border.color:"#ccc"
                }
                padding:10

            }

            Rectangle{
                RowLayout{
                    Layout.alignment: Qt.AlignVCenter
                    // anchors.centerIn:parent
                    spacing:8

                    CheckBox{
                        Layout.alignment: Qt.AlignVCenter
                        width:16
                        height:16

                    }
                    Label {
                        text: "Remember for 30 days"
                        font.pixelSize: 12
                        font.family: productSansBold.name
                        color:"black"
                        // horizontalAlignment: Text.AlignHCenter
                        Layout.alignment: Qt.AlignVCenter


                    }

                }


            }
            Item {
                height: 2
            }
            Button {
                Layout.fillWidth:true
                Layout.preferredHeight:40

                background: Rectangle {
                    color: "#000000"
                    radius: 5
                }
                contentItem:Text{
                    text:"Login"
                    color:"white"
                    font.bold:true
                    // anchors.centerIn:parent
                    horizontalAlignment: Text.AlignHCenter
                    Layout.alignment: Qt.AlignVCenter
                    font.family: productSansBold.name
                }

                onClicked: {
                    loginHandler.validateLogin(usernameField.text, passwordField.text)
                }


            }
            Connections {
                target: loginHandler
                function onLoginResult(title, message) {
                    if (title === "Success") {

                        appWin.loggedIn = true
                    } else {
                        errorText.text=message
                        errorDialog.title=title
                        errorDialog.open()
                        console.log(message)
                    }
                }
            }
            Label {
                textFormat: Text.RichText
                text: "Don't have an account? <a href='signUpPage' style='font-weight:bold; color: blue; text-decoration: underline;'>Sign up</a>"
                font.pixelSize: 12
                font.family: productSansBold.name
                color:"black"
                horizontalAlignment: Text.AlignHCenter
                Layout.alignment: Qt.AlignHCenter
                onLinkActivated: {
                    if (link === "signup") {

                        console.log("Sign up link clicked")
                    }
                }
            }
        }

    }








}
