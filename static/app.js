
async function fetchChatbotFeatures(apiKey) {
try {
    const response = await fetch(`/get_chatbot_features?apikey=${apiKey}`);
    const data = await response.json();

    if (data.chatbot_features) {
    // Process and display chatbot features as needed
        console.log('Chatbot features:', data.chatbot_features[0]);
        document.getElementById("chatbot_name").innerHTML=data.chatbot_features[0].chatbot_name;
        document.getElementById("chatbox_write").placeholder=data.chatbot_features[0].chatbot_write;
        document.getElementById("chatbox_text").innerHTML=data.chatbot_features[0].chatbot_text;
    } else {
    console.error('Error fetching chatbot features');
    }
    const response2 = await fetch(`/get_chatbot_image?apikey=${apiKey}`);
    const data2 = await response2.json();

    if (data.chatbot_features) {
        const imageBase64 = data2.chatbot_image;
        document.getElementById('image').src = 'data:image/jpeg;base64,' + imageBase64;
    } else {
        console.error('Error fetching chatbot features');
    }
    
} catch (error) {
    console.error('Error fetching chatbot features:', error);
}
}



// Fetch chatbot features when the document starts
document.addEventListener('DOMContentLoaded', function () {
    const myElement = document.getElementById('chatbot');
    const apiKey = myElement.getAttribute('apikey');
   fetchChatbotFeatures(apiKey);
});


document.write('<div class="container">');
document.write('<div class="chatbox">');
document.write('<div class="chatbox__support">');
document.write('<div class="chatbox__header">');
document.write('<div class="chatbox__image--header"><img id="image" width=100 heigth=100 src="https://img.icons8.com/color/48/000000/circled-user-female-skin-type-5--v1.png" alt="image"></div>');
document.write('<div class="chatbox__content--header">');
document.write('<h4 id="chatbot_name" class="chatbox__heading--header"></h4>');
document.write('<p id="chatbox_text" class="chatbox__description--header"></p>');
document.write('</div>');
document.write('</div>');
document.write('<div class="chatbox__messages"><div></div></div>');
document.write('<div class="chatbox__footer">');
document.write('<input id="chatbox_write" type="text" placeholder="Write a message...">');
document.write('<button class="chatbox__send--footer send__button">Send</button>');
document.write('</div>');
document.write('</div>');
document.write('<div class="chatbox__button">');
document.write('<button><img width=50 heigth=50 src="https://media.tenor.com/8QmnopMNjrwAAAAC/chat.gif" /></button>');
document.write('</div>');
document.write('</div>');

class Chatbox {
    constructor() {
        this.args = {
            openButton: document.querySelector('.chatbox__button'),
            chatBox: document.querySelector('.chatbox__support'),
            sendButton: document.querySelector('.send__button')
        }

        this.state = false;
        this.messages = [];
    }

    display() {
        const {openButton, chatBox, sendButton} = this.args
        openButton.addEventListener('click', () => this.toggleState(chatBox))
        sendButton.addEventListener('click', () => this.onSendButton(chatBox))
        const node = chatBox.querySelector('input');
        node.addEventListener("keyup", ({key}) => {
            if (key === "Enter") {
                this.onSendButton(chatBox)
            }
        })
    }
    
    toggleState(chatbox) {
        this.state = !this.state;

        // show or hides the box
        if(this.state) {
            chatbox.classList.add('chatbox--active')
        } else {
            chatbox.classList.remove('chatbox--active')
        }
    }

    onSendButton(chatbox) {
        const myElement = document.getElementById('chatbot');

        if (myElement) {
            // Get the values of the data attributes
            const apiKey = myElement.getAttribute('apikey');
            const userId = myElement.getAttribute('userid');


            var textField = chatbox.querySelector('input');
            let text1 = textField.value;
            if (text1 === "") {
                return;
            }
        
            let msg1 = { name: "User", message: text1 };
            this.messages.push(msg1);
        
            fetch('/predict?apikey=' + apiKey + '&userid=' + userId, {
                method: 'POST',
                body: JSON.stringify({ message: text1 }),
                mode: 'cors',
                headers: {
                    'Content-Type': 'application/json'
                },
            })
            .then(r => r.json())
            .then(r => {
                let msg2 = { name: "Sam", message: r.answer };
                this.messages.push(msg2);
                this.updateChatText(chatbox);
                textField.value = '';
            })
            .catch((error) => {
                console.error('Error:', error);
                this.updateChatText(chatbox);
                textField.value = '';
            });
        } else {
            console.error('Element with ID "myElement" not found.');
        }
    
        
    }
    

    updateChatText(chatbox) {
        var html = '';
        this.messages.slice().reverse().forEach(function(item, index) {
            if (item.name === "Sam")
            {
                html += '<div class="messages__item messages__item--visitor">' + item.message + '</div>'
            }
            else
            {
                html += '<div class="messages__item messages__item--operator">' + item.message + '</div>'
            }
          });

        const chatmessage = chatbox.querySelector('.chatbox__messages');
        chatmessage.innerHTML = html;
    }
}


const chatbox = new Chatbox();
chatbox.display();