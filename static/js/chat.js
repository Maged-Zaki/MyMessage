const socket = io();

$(document).ready(function () {
    // Function to handle the click event on the send button
    function sendMessage() {
        // Find the relevant elements within the chat-card
        var chatCard = this.closest('.chat-card');
        var messageElement = chatCard.querySelector(".text-box-message");
        var recipient_idElement = chatCard.querySelector(".recipient_id");
        var conversation_id_idElement = chatCard.querySelector(".conversation_id");


        var message = messageElement.value;
        var recipient_id = recipient_idElement.value;
        var conversation_id = conversation_id_idElement.value;
            

        

        // fetch and send data to python
        var endpointURL = "/chat/send-message";
        var dataToSend = { message: message, recipient_id: recipient_id, conversation_id: conversation_id };

        fetch(endpointURL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(dataToSend)
        
        });

        if (message != "")
        {
            socket.emit('new_message', {'message': message, 'recipient_id': recipient_id, 'conversation_id': conversation_id})
        }




        // Clear the message input field
        messageElement.value = "";
    }

    // Use classes to select the elements for event listeners
    var sendMessageButtons = document.querySelectorAll(".send-message-button");
    if (sendMessageButtons) {
        sendMessageButtons.forEach((button) => {
            button.addEventListener("click", sendMessage);
        });
    }

    
    var messageInputs = document.querySelectorAll(".text-box-message");
    if (messageInputs) {
        messageInputs.forEach((input) => {
            input.addEventListener("keydown", function (event) {
                if (event.key === "Enter") {
                    sendMessage.call(input); // Use call() to pass the input element as "this" inside sendMessage
                    event.preventDefault();
                }
            });
        });
    }

    // update current html for the sender
    socket.on("send_message", function(data) {
        var message = data["message"];
        var sender_id = data["sender_id"];
        var conversation_id = data["conversation_id"];
        var timestamp = data["timestamp"];

        // Find the chat container element by conversation_id
        var msg_card = document.getElementById(`msg_card_body-id-${conversation_id}`);

        var newMessageElement = document.createElement("div");
        newMessageElement.className = "d-flex justify-content-end mb-4";
        newMessageElement.innerHTML = `
        <div class="msg_cotainer_send">
            ${message}
            <span class="msg_time_send">${timestamp}</span>
        </div>
        <div class="img_cont_msg">
            <img src="/static/images/uploaded_images/${sender_id}.png" class="rounded-circle user_img_msg">
        </div>
        </div>
    `;

    msg_card.insertAdjacentElement("afterbegin", newMessageElement);
    });
    
    
    // update current html for the recipient
    socket.on("receive_message", function(data) {
        var message = data["message"];
        var sender_id = data["sender_id"];
        var conversation_id = data["conversation_id"];
        var timestamp = data["timestamp"]
    
        // Find the chat container element by conversation_id
        var msg_card = document.getElementById(`msg_card_body-id-${conversation_id}`);
    
        // Create the new message element
        var newMessageElement = document.createElement("div");
        newMessageElement.className = "d-flex justify-content-start mb-4";
        newMessageElement.innerHTML = `
            <div class="img_cont_msg">
                <img src="/static/images/uploaded_images/${sender_id}.png" class="rounded-circle user_img_msg">
            </div>
            <div class="msg_cotainer">
                ${message}
                <span class="msg_time">${timestamp}</span>
            </div>
        `;
    
        // Insert the new message element as the first child of the chat container
        msg_card.insertAdjacentElement("afterbegin", newMessageElement);
    });
    
    
    
    
});





    const contactCards = document.querySelectorAll('.contact-card');
  const chatCards = document.querySelectorAll('.chat-card');
  
  contactCards.forEach((contactCard) => {
      contactCard.addEventListener('click', () => {
          const targetChatId = contactCard.dataset.target;
  
          chatCards.forEach((chatCard) => {
              if (chatCard.id === targetChatId) {
                  chatCard.classList.remove('d-none');
              } else {
                  chatCard.classList.add('d-none');
              }
          });
      });
  });


// chat.js

document.querySelectorAll(".action_menu_btn").forEach(button => {
    button.addEventListener("click", function () {
        const actionMenuContainer = this.parentElement.querySelector(".action_menu");
        actionMenuContainer.classList.toggle("show");
    });
});

document.querySelectorAll(".view-profile-item").forEach(item => {
    item.addEventListener("click", function () {
        const recipientId = this.dataset.recipientId;
        window.location.href = `/users/${recipientId}`;
    });
});

document.querySelectorAll(".delete-conversation-item").forEach(item => {
    item.addEventListener("click", function () {
        const recipientId = this.dataset.recipientId;
        window.location.href = `/delete-conversation/${recipientId}`;
    });
});









