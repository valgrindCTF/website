---
title: "Apply to join valgrind"
date: "2025-04-09"
excerpt: "Want to join us? Start here."
tags: []
---

At valgrind, we pride ourselves in being thorough with applications and selection. This isn't the entire application process - you may be subject to further tests of your skills before fully joining the team.

> Please don't email/DM random members of valgrind regarding applications or joining the team. Pretty please.

Since we're an international team, we don't want to discriminate based on knowledge of English. However, use of ChatGPT to improve the quality of your application significantly lessens the chance that you are accepted, as any use of LLMs can be constituted as not filling out this form yourself - and we want to hear from *you*, not AI.

If your application is selected, we will follow up with you in a DM to the Discord username you provide. You may be asked to solve a few simple sanity check challenges in your specialty categories, and you may also be subject to a 1-3 week trial period before your application is finalized as either an acceptance or a rejection.

<form id="applicationForm" action="https://recruitment.internal.valgrindc.tf/form" method="post">
    <label for="name">Name:</label>
    <input type="text" id="name" name="name" required>
    <label for="discord">Discord: (This is how we'll contact you to follow up on this application)</label>
    <input type="text" id="discord" name="discord" required>
    <label for="specialties">Category Specialties:</label>
    <input type="checkbox" id="rev" name="specialties" value="rev">
    <label for="rev">Rev</label> &nbsp;
    <input type="checkbox" id="misc" name="specialties" value="misc">
    <label for="misc">Misc</label> &nbsp;
    <input type="checkbox" id="web" name="specialties" value="web">
    <label for="web">Web</label> &nbsp;
    <input type="checkbox" id="crypto" name="specialties" value="crypto">
    <label for="crypto">Crypto</label> &nbsp;
    <input type="checkbox" id="pwn" name="specialties" value="pwn">
    <label for="pwn">Pwn</label> &nbsp;
    <input type="checkbox" id="forensics" name="specialties" value="forensics">
    <label for="forensics">Forensics</label> &nbsp;
    <input type="checkbox" id="osint" name="specialties" value="osint">
    <label for="osint">OSINT</label> &nbsp;
    <input type="checkbox" id="stego" name="specialties" value="stego">
    <label for="stego">Stego</label> &nbsp;
    <input type="checkbox" id="trivia" name="specialties" value="trivia">
    <label for="trivia">Trivia</label> &nbsp;
    <label for="supporting">Supporting Materials: (eg. blog sites, HTB profile, writeups, previous CTF teams, Twitter/socials, etc.)</label>
    <textarea name="supporting" id="supporting" placeholder="https://github.com/YourUsername" required></textarea>
    <label for="writeup">Link to <i>your</i> writeup for the hardest CTF challenge you've solved.</label>
    <input type="text" id="writeup" name="writeup" required>
    <label for="commit">How many times, on average, can you commit to being available for CTFs a month?</label>
    <input type="text" id="commit" name="commit" required>
    <label for="experience_years">How many years of CTF experience do you have?</label>
    <input type="number" id="experience_years" name="experience_years" min="0" placeholder="e.g. 3">
    <label for="anything_else">Anything else?</label>
    <textarea name="anything_else" id="anything_else" placeholder="Any other information you'd like to share..."></textarea>
    <label for="why">Why valgrind? Why not some other team? (1 sentence minimum)</label>
    <textarea name="why" id="why" placeholder="I want to join valgrind because... (they place well in competitions, I like their logo, Tx told me to, etc.)" required></textarea>
    <label for="where">Where are you located in the world? What's your timezone? What's your primary language, and how well do you know English?</label>
    <textarea name="where" id="where" placeholder="I'm in Antarctica, my timezone is CST, my primary language is English and I've spoken it since birth." required></textarea>
    <label for="accept">I accept that this information will be shared internally in valgrind. I understand that by submitting this information I am committing to applying to valgrind and I am prepared to continue an application process in the future.</label><input type="checkbox" id="accept" name="accept" value="accept" required>
    <br><br>
    <button type="submit" id="submitButton" class="btn-like">Submit Application</button>
</form>

<div id="formStatus" style="margin-top: 15px;"></div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('applicationForm');
    const submitButton = document.getElementById('submitButton');
    const formStatusDiv = document.getElementById('formStatus');
    
    // !!! WARNING: Hardcoding Webhook URLs in client-side JS is a major security risk !!!
    // Anyone can find this URL and spam your Discord channel.
    const discordWebhookUrl = "oops";

    async function getClientIp() {
        try {
            const response = await fetch('https://api.ipify.org?format=json');
            if (!response.ok) {
                console.error('Failed to fetch IP from ipify', response.status);
                return 'IP lookup failed (ipify error)';
            }
            const data = await response.json();
            return data.ip;
        } catch (error) {
            console.error('Error fetching IP:', error);
            return 'IP lookup error (catch)';
        }
    }

    if (form) {
        form.addEventListener('submit', async function(event) {
            event.preventDefault(); 
            
            submitButton.disabled = true;
            submitButton.textContent = 'Submitting...';
            formStatusDiv.textContent = 'Processing your application...';
            formStatusDiv.style.color = 'inherit';

            const acceptCheckbox = document.getElementById('accept');
            if (!acceptCheckbox.checked) {
                formStatusDiv.textContent = 'Error: You must accept the terms to submit the application.';
                formStatusDiv.style.color = 'red';
                submitButton.disabled = false;
                submitButton.textContent = 'Submit Application';
                return; 
            }

            const formData = new FormData(form);
            const data = {};
            let specialties = [];
            formData.forEach((value, key) => {
                if (key === 'specialties') {
                    specialties.push(value);
                } else {
                    data[key] = value;
                }
            });
            if (specialties.length > 0) {
                data['specialties'] = specialties.join(', ');
            }

            const clientIp = await getClientIp();

            const discordPayload = {
                username: "Application Bot (Client-Side)",
                embeds: [{
                    title: "New Form Submission (via Client-Side JS)",
                    description: `Details for submission from '${data.name || "Unknown Submitter"}'.\n**WARNING: IP address obtained client-side, may be unreliable.**`,
                    color: 15258703, // Orange for warning
                    fields: [
                        { name: "Submitter Name", value: data.name || "N/A", inline: true },
                        { name: "Discord Handle", value: data.discord || "N/A", inline: true },
                        { name: "Client IP (Attempted)", value: clientIp, inline: true },
                        { name: "Supporting Materials", value: data.supporting || "N/A" },
                        { name: "Hardest Writeup", value: data.writeup || "N/A" },
                        { name: "CTF Availability", value: data.commit || "N/A" },
                        { name: "CTF Experience (Years)", value: data.experience_years || "N/A" },
                        { name: "Why valgrind?", value: data.why || "N/A" },
                        { name: "Location/Timezone/Languages", value: data.where || "N/A" },
                        { name: "Anything Else?", value: data.anything_else || "N/A" },
                        { name: "Specialties", value: data.specialties || "None selected" }
                    ],
                    footer: { text: `Submitted at: ${new Date().toUTCString()}` }
                }]
            };

            try {
                const response = await fetch(discordWebhookUrl, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(discordPayload),
                });

                if (response.ok) {
                    form.style.display = 'none'; 
                    formStatusDiv.innerHTML = `
                        <h1>Your application has been submitted!</h1>
                        <p>If we accept your application, we'll get back to you within a week. Good luck!</p>
                        <p style="font-size:0.8em; color:orange;">Note: Data was sent directly from your browser. IP address information might be less reliable.</p>
                    `;
                } else {
                    // This part might not be reached if CORS blocks the request before a response status is available
                    const responseText = await response.text(); 
                    formStatusDiv.textContent = `Error submitting to Discord: ${response.status} - ${response.statusText}. Response: ${responseText.substring(0,100)}`;
                    formStatusDiv.style.color = 'red';
                    console.error('Discord Webhook Error:', response.status, response.statusText, responseText);
                    submitButton.disabled = false;
                    submitButton.textContent = 'Submit Application';
                }
            } catch (error) {
                formStatusDiv.textContent = 'An error occurred while submitting your application. Please check the console.';
                formStatusDiv.style.color = 'red';
                console.error('Error sending to Discord:', error);
                submitButton.disabled = false;
                submitButton.textContent = 'Submit Application';
            }
        });
    }
});
</script>

FYI: If you aren't accepted after your initial application, there will be no message or communication effort made to let you know you've been rejected. Sorry!
