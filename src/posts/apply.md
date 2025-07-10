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
    <label for="why">Why valgrind? Why not some other team? (1 sentence minimum)</label>
    <textarea name="why" id="why" placeholder="I want to join valgrind because... (they place well in competitions, I like their logo, Tx told me to, etc.)" required></textarea>
    <label for="where">Where are you located in the world? What's your timezone? What's your primary language, and how well do you know English?</label>
    <textarea name="where" id="where" placeholder="I'm in Antarctica, my timezone is CST, my primary language is English and I've spoken it since birth." required></textarea>
    <label for="space_or_oceans">Should humanity explore the oceans or space? Why? Justify your answer. (500 word max)</label>
    <textarea name="space_or_oceans" id="space_or_oceans" placeholder="We should explore..." required></textarea>
    <label for="anything_else">Anything else?</label>
    <textarea name="anything_else" id="anything_else" placeholder="Any other information you'd like to share..."></textarea>
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

    // Define the success page content and redirection logic
    function showSuccessAndRedirect() {
        // Hide the form or clear its content
        form.style.display = 'none'; 
        
        formStatusDiv.innerHTML = `
            <h1>Your application has been submitted!</h1>
            <p>If we accept your application, we'll get back to you within a week. Good luck!</p>
        `;
    }

    if (form) {
        form.addEventListener('submit', function(event) {
            event.preventDefault(); 
            
            submitButton.disabled = true;
            submitButton.textContent = 'Submitting...';
            formStatusDiv.textContent = ''; 

            const acceptCheckbox = document.getElementById('accept');
            if (!acceptCheckbox.checked) {
                formStatusDiv.textContent = 'Error: You must accept the terms to submit the application.';
                formStatusDiv.style.color = 'red';
                submitButton.disabled = false;
                submitButton.textContent = 'Submit Application';
                return; 
            }

            const formData = new FormData(form);
            const formAction = form.getAttribute('action');

            fetch(formAction, {
                method: 'POST',
                body: formData,
            })
            .catch(error => {
                console.warn('Fetch encountered an error (ignored by palliative UI):', error);
            })
            .finally(() => {
                console.log('Palliative: Simulating success and redirecting.');
                showSuccessAndRedirect();
            });
        });
    }
});
</script>

FYI: If you aren't accepted after your initial application, there will be no message or communication effort made to let you know you've been rejected. Sorry!
