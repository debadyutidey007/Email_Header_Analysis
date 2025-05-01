# phishing_quiz_app.py
import os
import random
from flask import Flask, request, render_template_string, session, redirect, url_for

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "phishing_awareness_quiz_secret")

# Collection of phishing awareness questions
questions = [
    {
        "question": "An email claims to be from your bank, stating your account will be suspended unless you verify your information immediately. What should you do?",
        "options": {
            "a": "Click the link in the email and enter your banking credentials",
            "b": "Reply to the email with your account details",
            "c": "Call your bank using the number from their official website or the back of your card",
            "d": "Forward the email to your friends to see if they received it too"
        },
        "correct_answer": "c",
        "explanation": "Always verify such requests by contacting your bank through official channels. Banks will never ask for your credentials via email. This is a common phishing tactic that creates urgency to manipulate you into making hasty decisions.",
        "category": "Financial"
    },
    {
        "question": "You receive an email with an attachment from someone claiming to be a delivery company about a package you weren't expecting. What is the safest action?",
        "options": {
            "a": "Open the attachment to see what the package is",
            "b": "Reply asking for more details about the package",
            "c": "Delete the email and do not open the attachment",
            "d": "Forward the email to your colleague to see if they ordered something"
        },
        "correct_answer": "c",
        "explanation": "Unexpected attachments are a common way to distribute malware. If you weren't expecting a package, this is likely a phishing attempt. Legitimate delivery companies typically don't send unsolicited attachments.",
        "category": "Email Attachments"
    },
    {
        "question": "You receive a text message saying you've won a prize and need to click a link to claim it. What should you do?",
        "options": {
            "a": "Click the link to see what you've won",
            "b": "Reply asking for more information",
            "c": "Ignore and delete the message",
            "d": "Share the link with friends so they can win too"
        },
        "correct_answer": "c",
        "explanation": "Unsolicited prize notifications are almost always scams. These 'smishing' attempts (SMS phishing) try to get you to click malicious links that may steal your information or install malware.",
        "category": "Smishing"
    },
    {
        "question": "Which of the following email addresses is most likely to be legitimate?",
        "options": {
            "a": "support@amazon-service.com",
            "b": "amazon_support@hotmail.com",
            "c": "help@amazon.com",
            "d": "amazon.payments@secure-site.net"
        },
        "correct_answer": "c",
        "explanation": "Legitimate organizations use email domains that match their official website. 'help@amazon.com' follows this pattern. Other variations with hyphens, additional words, or generic email providers are typical phishing tactics.",
        "category": "Email Authentication"
    },
    {
        "question": "A message pops up while browsing, saying your computer is infected and you should call a number for technical support. What should you do?",
        "options": {
            "a": "Call the number immediately to fix your computer",
            "b": "Click the 'Clean Computer Now' button in the pop-up",
            "c": "Close the browser or force quit the application",
            "d": "Enter your administrator password when prompted to remove the virus"
        },
        "correct_answer": "c",
        "explanation": "This is a common tech support scam. These pop-ups are designed to frighten you into calling fake support numbers or downloading malware. Close the browser or force quit the application, and run a scan with legitimate antivirus software.",
        "category": "Tech Support Scams"
    },
    {
        "question": "Which of these is a warning sign of a phishing email?",
        "options": {
            "a": "The email addresses you by your full name",
            "b": "The email comes from a company you do business with",
            "c": "There are spelling and grammatical errors in the email",
            "d": "The email was received during business hours"
        },
        "correct_answer": "c",
        "explanation": "Legitimate companies typically have quality control processes for their communications. Spelling and grammatical errors are common in phishing emails, often because attackers may not be native speakers of the language or they're trying to bypass spam filters.",
        "category": "Email Red Flags"
    },
    {
        "question": "Your CEO sends you an urgent email asking you to purchase gift cards and send him the codes immediately. What should you do?",
        "options": {
            "a": "Purchase the gift cards right away since it's from the CEO",
            "b": "Verify the request through another communication channel directly with the CEO",
            "c": "Forward the email to your coworker to handle it",
            "d": "Reply asking what store to buy the gift cards from"
        },
        "correct_answer": "b",
        "explanation": "This is a classic CEO fraud or Business Email Compromise (BEC) scam. Always verify unusual requests, especially those involving payments or gift cards, through a different channel like a phone call, even if they appear to come from authority figures.",
        "category": "Business Email Compromise"
    },
    {
        "question": "You receive an email with a link that says 'Click here to reset your password, your account has been compromised.' What should you do?",
        "options": {
            "a": "Click the link immediately and reset your password",
            "b": "Forward the email to all your contacts as a warning",
            "c": "Reply to the email asking for more information",
            "d": "Go directly to the website by typing the URL in your browser and check your account"
        },
        "correct_answer": "d",
        "explanation": "Never click on links in emails claiming your account has been compromised. Instead, access the website directly by typing the URL in your browser or using a bookmark, then check your account or contact customer support.",
        "category": "Account Security"
    },
    {
        "question": "Which of these password practices helps protect against phishing attacks?",
        "options": {
            "a": "Using the same password across multiple sites for consistency",
            "b": "Using two-factor authentication when available",
            "c": "Writing down passwords on a note near your computer",
            "d": "Sharing passwords with trusted colleagues"
        },
        "correct_answer": "b",
        "explanation": "Two-factor authentication provides an additional layer of security. Even if phishers obtain your password, they would still need the second factor (like a code from your phone) to access your account.",
        "category": "Authentication"
    },
    {
        "question": "A social media message from your friend contains only a link and says 'Is this you in this video?' What is the safest response?",
        "options": {
            "a": "Click the link to check the video",
            "b": "Reply asking what the video is about",
            "c": "Contact your friend through another method to verify they sent the message",
            "d": "Share the link with others to see if they recognize the video"
        },
        "correct_answer": "c",
        "explanation": "This is a common social media phishing tactic. Hackers compromise accounts and send malicious links to all contacts. Verify with your friend through another communication channel before clicking any suspicious links.",
        "category": "Social Media"
    }
]

# Examples of real phishing attempts for educational purposes
phishing_examples = [
    {
        "title": "Fake Netflix Account Verification",
        "description": "This email claims your Netflix account needs verification, but notice the sender's email address isn't from netflix.com. The link would take you to a fake Netflix login page.",
        "red_flags": [
            "Sender: netflix-support@accounts-verify.com (not netflix.com)",
            "Urgency: 'Account will be suspended in 24 hours'",
            "Generic greeting: 'Dear Customer' instead of your name",
            "Grammatical errors in the email body",
            "Hover over the link shows a suspicious URL, not netflix.com"
        ],
        "category": "Entertainment Services"
    },
    {
        "title": "COVID-19 Relief Payment Scam",
        "description": "This phishing email claims to offer government COVID relief payments, asking for personal and banking information to 'process your payment'.",
        "red_flags": [
            "Sender pretends to be from a government agency but uses a gmail.com address",
            "Contains spelling errors and unusual formatting",
            "Asks for sensitive information like SSN and bank details via an unsecured form",
            "The URL in the email doesn't match official government websites",
            "Creates urgency with 'limited time offer' language"
        ],
        "category": "Government Impersonation"
    },
    {
        "title": "Fake IT Support Alert",
        "description": "This email poses as your company's IT department, claiming suspicious activity on your account and asking you to verify your credentials immediately.",
        "red_flags": [
            "Generic greeting rather than addressing you by name",
            "Sender's email domain doesn't match your company's actual domain",
            "Creates urgency with threatening language about account suspension",
            "The 'Verify Now' button links to a non-company website",
            "Contains vague details about the 'suspicious activity'"
        ],
        "category": "Corporate Impersonation"
    }
]

# Application routes
@app.route('/')
def index():
    """Render the home page"""
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Phishing Awareness Quiz - Home</title>
        <!-- Bootstrap CSS -->
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
        <!-- Font Awesome -->
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
        <style>
            :root {
                --primary-color: #4e73df;
                --secondary-color: #224abe;
                --accent-color: #e74a3b;
                --success-color: #1cc88a;
                --info-color: #36b9cc;
                --warning-color: #f6c23e;
                --dark-bg: #222;
                --darker-bg: #1a1a1a;
                --card-bg: #333;
                --text-color: #fff;
            }
            
            body {
                font-family: 'Nunito', sans-serif;
                background-color: var(--dark-bg);
                color: var(--text-color);
                line-height: 1.6;
                min-height: 100vh;
                display: flex;
                flex-direction: column;
            }
            
            .navbar {
                background-color: var(--darker-bg) !important;
            }
            
            .navbar-brand {
                font-weight: 800;
                font-size: 1.5rem;
            }
            
            main {
                flex: 1;
            }
            
            .card {
                transition: transform 0.3s, box-shadow 0.3s;
                border-radius: 0.8rem;
                overflow: hidden;
                background-color: var(--card-bg);
                border: none;
            }
            
            .card:hover {
                transform: translateY(-5px);
                box-shadow: 0 1rem 3rem rgba(0, 0, 0, 0.3);
            }
            
            .btn-primary {
                background-color: var(--primary-color);
                border-color: var(--primary-color);
                transition: all 0.3s;
            }
            
            .btn-primary:hover {
                background-color: var(--secondary-color);
                border-color: var(--secondary-color);
                transform: translateY(-2px);
                box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.2);
            }
            
            .btn-lg {
                padding: 0.8rem 2rem;
                font-size: 1.25rem;
                font-weight: 600;
                letter-spacing: 0.5px;
            }
            
            .text-primary {
                color: var(--primary-color) !important;
            }
            
            .bg-primary {
                background-color: var(--primary-color) !important;
            }
            
            .card-header {
                background-color: var(--primary-color);
                color: white;
            }
            
            .alert-info {
                background-color: rgba(54, 185, 204, 0.1);
                color: white;
                border-color: var(--info-color);
            }
            
            footer {
                background-color: var(--darker-bg);
                color: var(--text-color);
                padding: 1.5rem 0;
                margin-top: 3rem;
                border-top: 1px solid rgba(255, 255, 255, 0.1);
            }
            
            /* Animations */
            @keyframes fadeIn {
                from { opacity: 0; transform: translateY(20px); }
                to { opacity: 1; transform: translateY(0); }
            }
            
            .fade-in {
                animation: fadeIn 0.6s ease-out forwards;
            }
            
            .delay-1 { animation-delay: 0.1s; }
            .delay-2 { animation-delay: 0.2s; }
            .delay-3 { animation-delay: 0.3s; }
            .delay-4 { animation-delay: 0.4s; }
        </style>
    </head>
    <body>
        <nav class="navbar navbar-expand-lg navbar-dark">
            <div class="container">
                <a class="navbar-brand d-flex align-items-center" href="/">
                    <i class="fas fa-shield-alt text-primary me-2"></i>Phishing Awareness Quiz
                </a>
            </div>
        </nav>

        <main class="container my-4">
            <div class="row justify-content-center">
                <div class="col-lg-8">
                    <div class="card shadow-lg border-0 mb-4 fade-in">
                        <div class="card-body p-5 text-center">
                            <div class="mb-4">
                                <i class="fas fa-shield-alt text-primary fa-5x mb-4"></i>
                                <h1 class="display-4 fw-bold">Phishing Awareness Quiz</h1>
                                <p class="lead fs-4">Test your knowledge about recognizing and avoiding phishing attempts</p>
                            </div>
            
                            <div class="alert alert-info shadow-sm" role="alert">
                                <div class="d-flex">
                                    <div class="flex-shrink-0">
                                        <i class="fas fa-info-circle fa-2x me-3"></i>
                                    </div>
                                    <div>
                                        <h4 class="alert-heading">Did you know?</h4>
                                        <p class="mb-0">Over 90% of cyber attacks begin with a phishing email. Learning to identify these threats is crucial for your online safety.</p>
                                    </div>
                                </div>
                            </div>
            
                            <a href="/start_quiz" class="btn btn-primary btn-lg px-5 py-3 mt-4 shadow-sm">
                                <i class="fas fa-play-circle me-2"></i>Start Quiz
                            </a>
                        </div>
                    </div>
            
                    <div class="card shadow border-0 fade-in delay-2">
                        <div class="card-header bg-primary text-white">
                            <h3 class="h4 mb-0">
                                <i class="fas fa-graduation-cap me-2"></i>What You'll Learn
                            </h3>
                        </div>
                        <div class="card-body p-4">
                            <div class="row g-4">
                                <div class="col-md-6 fade-in delay-1">
                                    <div class="d-flex h-100">
                                        <div class="flex-shrink-0">
                                            <div style="background-color: rgba(78, 115, 223, 0.1);" class="p-3 rounded-circle">
                                                <i class="fas fa-search text-primary fa-2x"></i>
                                            </div>
                                        </div>
                                        <div class="ms-3">
                                            <h5 class="fw-bold">Identify Warning Signs</h5>
                                            <p>Learn to spot the telltale signs of phishing attempts across various platforms.</p>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-6 fade-in delay-2">
                                    <div class="d-flex h-100">
                                        <div class="flex-shrink-0">
                                            <div style="background-color: rgba(78, 115, 223, 0.1);" class="p-3 rounded-circle">
                                                <i class="fas fa-user-shield text-primary fa-2x"></i>
                                            </div>
                                        </div>
                                        <div class="ms-3">
                                            <h5 class="fw-bold">Protect Your Information</h5>
                                            <p>Discover best practices for safeguarding your personal and financial data.</p>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-6 fade-in delay-3">
                                    <div class="d-flex h-100">
                                        <div class="flex-shrink-0">
                                            <div style="background-color: rgba(78, 115, 223, 0.1);" class="p-3 rounded-circle">
                                                <i class="fas fa-exclamation-triangle text-primary fa-2x"></i>
                                            </div>
                                        </div>
                                        <div class="ms-3">
                                            <h5 class="fw-bold">Recognize Attack Types</h5>
                                            <p>Understand different phishing techniques from email to social media and SMS.</p>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-6 fade-in delay-4">
                                    <div class="d-flex h-100">
                                        <div class="flex-shrink-0">
                                            <div style="background-color: rgba(78, 115, 223, 0.1);" class="p-3 rounded-circle">
                                                <i class="fas fa-hand-paper text-primary fa-2x"></i>
                                            </div>
                                        </div>
                                        <div class="ms-3">
                                            <h5 class="fw-bold">Respond Appropriately</h5>
                                            <p>Learn the right actions to take when you encounter suspicious communications.</p>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </main>

        <footer class="text-light py-3">
            <div class="container text-center">
                <p class="mb-0">
                    <i class="fas fa-lock me-2 text-primary"></i>Phishing Awareness Quiz - Enhancing Cybersecurity Education
                </p>
            </div>
        </footer>

        <!-- Bootstrap JavaScript Bundle -->
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    """
    return render_template_string(html)

@app.route('/start_quiz')
def start_quiz():
    """Initialize the quiz and redirect to the first question"""
    # Initialize session variables
    session['current_question'] = 0
    session['score'] = 0
    session['answers'] = []
    session['questions'] = random.sample(questions, min(5, len(questions)))  # Select 5 random questions
    
    return redirect(url_for('quiz'))

@app.route('/quiz', methods=['GET', 'POST'])
def quiz():
    """Handle quiz questions and answers"""
    # Check if quiz is initialized
    if 'current_question' not in session:
        return redirect(url_for('index'))
    
    # Get question data
    current_idx = session['current_question']
    total_questions = len(session['questions'])
    
    # Check if quiz is finished
    if current_idx >= total_questions:
        return redirect(url_for('results'))
    
    question_data = session['questions'][current_idx]
    
    # Handle answer submission
    if request.method == 'POST':
        selected_answer = request.form.get('answer')
        
        if selected_answer:
            correct = selected_answer == question_data['correct_answer']
            
            # Save answer data
            session['answers'].append({
                'question': question_data['question'],
                'selected': selected_answer,
                'correct': correct,
                'correct_answer': question_data['correct_answer'],
                'explanation': question_data['explanation']
            })
            
            # Update score
            if correct:
                session['score'] += 1
            
            # Move to next question
            session['current_question'] += 1
            
            # If last question, go to results
            if session['current_question'] >= total_questions:
                return redirect(url_for('results'))
            
            return redirect(url_for('quiz'))
    
    # Calculate progress percentage
    progress = int((current_idx / total_questions) * 100)
    
    # Generate options HTML
    options_html = ""
    for key, value in question_data['options'].items():
        options_html += f"""
        <div class="option-card card p-3 fade-in" data-option="{key}">
            <div class="d-flex align-items-center">
                <div class="form-check">
                    <input class="form-check-input" type="radio" name="answer" id="option{key}" value="{key}">
                    <label class="form-check-label w-100" for="option{key}">
                        <strong>{key.upper()}.</strong> {value}
                    </label>
                </div>
            </div>
        </div>
        """
    
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Quiz Question {current_idx + 1} of {total_questions}</title>
        <!-- Bootstrap CSS -->
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
        <!-- Font Awesome -->
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
        <!-- SweetAlert2 -->
        <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
        <style>
            :root {{
                --primary-color: #4e73df;
                --secondary-color: #224abe;
                --accent-color: #e74a3b;
                --success-color: #1cc88a;
                --info-color: #36b9cc;
                --warning-color: #f6c23e;
                --dark-bg: #222;
                --darker-bg: #1a1a1a;
                --card-bg: #333;
                --text-color: #fff;
            }}
            
            body {{
                font-family: 'Nunito', sans-serif;
                background-color: var(--dark-bg);
                color: var(--text-color);
                line-height: 1.6;
                min-height: 100vh;
                display: flex;
                flex-direction: column;
            }}
            
            .navbar {{
                background-color: var(--darker-bg) !important;
            }}
            
            .navbar-brand {{
                font-weight: 800;
                font-size: 1.5rem;
            }}
            
            main {{
                flex: 1;
            }}
            
            .card {{
                transition: transform 0.3s, box-shadow 0.3s;
                border-radius: 0.8rem;
                overflow: hidden;
                background-color: var(--card-bg);
                border: none;
            }}
            
            .card:hover {{
                transform: translateY(-5px);
                box-shadow: 0 1rem 3rem rgba(0, 0, 0, 0.3);
            }}
            
            .btn-primary {{
                background-color: var(--primary-color);
                border-color: var(--primary-color);
                transition: all 0.3s;
            }}
            
            .btn-primary:hover {{
                background-color: var(--secondary-color);
                border-color: var(--secondary-color);
                transform: translateY(-2px);
                box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.2);
            }}
            
            .btn-lg {{
                padding: 0.8rem 2rem;
                font-size: 1.25rem;
                font-weight: 600;
                letter-spacing: 0.5px;
            }}
            
            .progress-bar {{
                background-color: var(--primary-color);
                height: 0.8rem;
                transition: width 0.6s ease;
            }}
            
            .option-card {{
                cursor: pointer;
                margin-bottom: 1rem;
                border: 2px solid rgba(255, 255, 255, 0.1);
                transition: all 0.3s;
                background-color: var(--card-bg);
            }}
            
            .option-card:hover {{
                border-color: var(--primary-color);
                background-color: rgba(78, 115, 223, 0.1);
            }}
            
            .option-card.selected {{
                border-color: var(--primary-color);
                background-color: rgba(78, 115, 223, 0.2);
            }}
            
            .badge {{
                font-size: 0.85rem;
                padding: 0.5rem 0.8rem;
                border-radius: 50rem;
                font-weight: 600;
            }}
            
            .text-primary {{
                color: var(--primary-color) !important;
            }}
            
            .bg-primary {{
                background-color: var(--primary-color) !important;
            }}
            
            .card-header {{
                background-color: var(--primary-color);
                color: white;
            }}
            
            .form-check-input:checked {{
                background-color: var(--primary-color);
                border-color: var(--primary-color);
            }}
            
            footer {{
                background-color: var(--darker-bg);
                color: var(--text-color);
                padding: 1.5rem 0;
                margin-top: 3rem;
                border-top: 1px solid rgba(255, 255, 255, 0.1);
            }}
            
            /* Animations */
            @keyframes fadeIn {{
                from {{ opacity: 0; transform: translateY(20px); }}
                to {{ opacity: 1; transform: translateY(0); }}
            }}
            
            .fade-in {{
                animation: fadeIn 0.6s ease-out forwards;
            }}
        </style>
    </head>
    <body>
        <nav class="navbar navbar-expand-lg navbar-dark">
            <div class="container">
                <a class="navbar-brand d-flex align-items-center" href="/">
                    <i class="fas fa-shield-alt text-primary me-2"></i>Phishing Awareness Quiz
                </a>
            </div>
        </nav>

        <main class="container my-4">
            <div class="row justify-content-center">
                <div class="col-lg-8">
                    <div class="card border-0 shadow-lg mb-4 fade-in">
                        <div class="card-header p-3">
                            <div class="d-flex justify-content-between align-items-center">
                                <h3 class="h5 mb-0">Question {current_idx + 1} of {total_questions}</h3>
                                <span class="badge bg-light text-dark">
                                    <i class="fas fa-bookmark me-1"></i>{question_data['category']}
                                </span>
                            </div>
                        </div>
                        <div class="card-body p-4">
                            <div class="progress mb-4" style="height: 10px;">
                                <div class="progress-bar" role="progressbar" style="width: {progress}%;" 
                                     aria-valuenow="{progress}" aria-valuemin="0" aria-valuemax="100"></div>
                            </div>
                            
                            <h4 class="mb-4">{question_data['question']}</h4>
                            
                            <form method="POST" id="quiz-form">
                                <div class="options-container">
                                    {options_html}
                                </div>
                                
                                <div class="d-grid mt-4">
                                    <button type="submit" class="btn btn-primary btn-lg">
                                        <i class="fas fa-arrow-right me-2"></i>Submit Answer
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </main>

        <footer class="text-light py-3">
            <div class="container text-center">
                <p class="mb-0">
                    <i class="fas fa-lock me-2 text-primary"></i>Phishing Awareness Quiz - Enhancing Cybersecurity Education
                </p>
            </div>
        </footer>

        <!-- Bootstrap JavaScript Bundle -->
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            document.addEventListener('DOMContentLoaded', function() {{
                const optionCards = document.querySelectorAll('.option-card');
                const radioInputs = document.querySelectorAll('input[type="radio"]');
                
                // Add click event to each option card
                optionCards.forEach(card => {{
                    card.addEventListener('click', function() {{
                        const option = this.dataset.option;
                        const radio = document.getElementById('option' + option);
                        
                        // Reset all selections
                        optionCards.forEach(c => c.classList.remove('selected'));
                        
                        // Select this option
                        radio.checked = true;
                        this.classList.add('selected');
                        
                        // Visual feedback
                        Swal.fire({{
                            title: 'Option ' + option.toUpperCase() + ' selected',
                            icon: 'info',
                            toast: true,
                            position: 'bottom-end',
                            showConfirmButton: false,
                            timer: 1000,
                            timerProgressBar: true
                        }});
                    }});
                }});
                
                // Form submission with validation
                document.getElementById('quiz-form').addEventListener('submit', function(e) {{
                    const selected = Array.from(radioInputs).some(input => input.checked);
                    
                    if (!selected) {{
                        e.preventDefault();
                        Swal.fire({{
                            title: 'Please select an answer',
                            text: 'You need to choose one of the options to continue',
                            icon: 'warning',
                            confirmButtonText: 'Ok',
                            confirmButtonColor: '#4e73df'
                        }});
                    }}
                }});
            }});
        </script>
    </body>
    </html>
    """
    return render_template_string(html)

@app.route('/results')
def results():
    """Show quiz results"""
    # Check if quiz was completed
    if 'score' not in session or 'answers' not in session or 'questions' not in session:
        return redirect(url_for('index'))
    
    # Get quiz data
    score = session['score']
    total = len(session['questions'])
    answers = session['answers']
    
    # Calculate percentage
    percentage = int((score / total) * 100) if total > 0 else 0
    
    # Determine performance level and feedback message
    if percentage >= 90:
        performance = "Expert"
        message = "Excellent job! You have a strong understanding of phishing threats and how to avoid them. Keep up the good work and continue to stay vigilant online."
    elif percentage >= 70:
        performance = "Proficient"
        message = "Good work! You have a solid grasp of phishing awareness. Review the questions you missed to further strengthen your knowledge."
    elif percentage >= 50:
        performance = "Adequate"
        message = "You have a basic understanding of phishing threats, but there's room for improvement. Pay close attention to the explanations for the questions you missed."
    else:
        performance = "Novice"
        message = "You should improve your phishing awareness skills. Reviewing the correct answers and explanations will help you better protect yourself online."
    
    # Generate answers HTML
    answers_html = ""
    for i, answer in enumerate(answers):
        correct_class = "answer-correct" if answer['correct'] else "answer-incorrect"
        answers_html += f"""
        <div class="answer-result {correct_class} mb-4">
            <div class="d-flex align-items-center mb-2">
                <div class="me-3">
                    <i class="fas {'fa-check-circle text-success' if answer['correct'] else 'fa-times-circle text-danger'} fa-2x"></i>
                </div>
                <h5 class="mb-0">{i+1}. {answer['question']}</h5>
            </div>
            <div class="ps-5 mt-2">
                <p><strong>Your answer:</strong> {answer['options'][answer['selected']] if 'options' in answer else 'Option ' + answer['selected'].upper()}</p>
                <p><strong>Correct answer:</strong> {answer['options'][answer['correct_answer']] if 'options' in answer else 'Option ' + answer['correct_answer'].upper()}</p>
                <div class="explanation-box mt-2">
                    <p class="mb-0"><strong>Explanation:</strong> {answer['explanation']}</p>
                </div>
            </div>
        </div>
        """
    
    # Generate phishing examples HTML
    examples_html = ""
    for example in phishing_examples:
        red_flags_html = ""
        for flag in example['red_flags']:
            red_flags_html += f"""
            <div class="red-flag-item">
                <i class="fas fa-exclamation-triangle text-danger me-2"></i> {flag}
            </div>
            """
        
        examples_html += f"""
        <div class="card mb-4 fade-in">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="mb-0"><i class="fas fa-fish-fins me-2"></i> {example['title']}</h5>
                <span class="badge bg-danger">{example['category']}</span>
            </div>
            <div class="card-body">
                <p>{example['description']}</p>
                <h6 class="mt-4 mb-3"><i class="fas fa-flag text-danger me-2"></i>Red Flags:</h6>
                {red_flags_html}
            </div>
        </div>
        """
    
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Quiz Results</title>
        <!-- Bootstrap CSS -->
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
        <!-- Font Awesome -->
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
        <style>
            :root {{
                --primary-color: #4e73df;
                --secondary-color: #224abe;
                --accent-color: #e74a3b;
                --success-color: #1cc88a;
                --info-color: #36b9cc;
                --warning-color: #f6c23e;
                --dark-bg: #222;
                --darker-bg: #1a1a1a;
                --card-bg: #333;
                --text-color: #fff;
            }}
            
            body {{
                font-family: 'Nunito', sans-serif;
                background-color: var(--dark-bg);
                color: var(--text-color);
                line-height: 1.6;
                min-height: 100vh;
                display: flex;
                flex-direction: column;
            }}
            
            .navbar {{
                background-color: var(--darker-bg) !important;
            }}
            
            .navbar-brand {{
                font-weight: 800;
                font-size: 1.5rem;
            }}
            
            main {{
                flex: 1;
            }}
            
            .card {{
                transition: transform 0.3s, box-shadow 0.3s;
                border-radius: 0.8rem;
                overflow: hidden;
                background-color: var(--card-bg);
                border: none;
            }}
            
            .card:hover {{
                transform: translateY(-5px);
                box-shadow: 0 1rem 3rem rgba(0, 0, 0, 0.3);
            }}
            
            .btn-primary {{
                background-color: var(--primary-color);
                border-color: var(--primary-color);
                transition: all 0.3s;
            }}
            
            .btn-primary:hover {{
                background-color: var(--secondary-color);
                border-color: var(--secondary-color);
                transform: translateY(-2px);
                box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.2);
            }}
            
            .btn-lg {{
                padding: 0.8rem 2rem;
                font-size: 1.25rem;
                font-weight: 600;
                letter-spacing: 0.5px;
            }}
            
            .explanation-box {{
                background-color: rgba(54, 185, 204, 0.1);
                border-left: 4px solid var(--info-color);
                padding: 1.5rem;
                border-radius: 0.5rem;
                margin-top: 2rem;
            }}
            
            .red-flag-item {{
                background-color: rgba(231, 74, 59, 0.1);
                border-left: 4px solid var(--accent-color);
                padding: 1rem;
                margin-bottom: 0.5rem;
                border-radius: 0.5rem;
            }}
            
            .stats-box {{
                text-align: center;
                padding: 2rem;
                border-radius: 1rem;
                margin-bottom: 2rem;
                background-color: rgba(28, 200, 138, 0.1);
                border: 2px solid var(--success-color);
            }}
            
            .stats-value {{
                font-size: 3rem;
                font-weight: 700;
                color: var(--success-color);
                margin-bottom: 0;
            }}
            
            .answer-result {{
                padding: 1rem;
                border-radius: 0.5rem;
                margin-bottom: 1rem;
            }}
            
            .answer-correct {{
                background-color: rgba(28, 200, 138, 0.1);
                border-left: 4px solid var(--success-color);
            }}
            
            .answer-incorrect {{
                background-color: rgba(231, 74, 59, 0.1);
                border-left: 4px solid var(--accent-color);
            }}
            
            .text-primary {{
                color: var(--primary-color) !important;
            }}
            
            .text-success {{
                color: var(--success-color) !important;
            }}
            
            .text-danger {{
                color: var(--accent-color) !important;
            }}
            
            .bg-primary {{
                background-color: var(--primary-color) !important;
            }}
            
            .card-header {{
                background-color: var(--primary-color);
                color: white;
            }}
            
            .alert-info {{
                background-color: rgba(54, 185, 204, 0.1);
                color: white;
                border-color: var(--info-color);
            }}
            
            footer {{
                background-color: var(--darker-bg);
                color: var(--text-color);
                padding: 1.5rem 0;
                margin-top: 3rem;
                border-top: 1px solid rgba(255, 255, 255, 0.1);
            }}
            
            /* Animations */
            @keyframes fadeIn {{
                from {{ opacity: 0; transform: translateY(20px); }}
                to {{ opacity: 1; transform: translateY(0); }}
            }}
            
            .fade-in {{
                animation: fadeIn 0.6s ease-out forwards;
            }}
        </style>
    </head>
    <body>
        <nav class="navbar navbar-expand-lg navbar-dark">
            <div class="container">
                <a class="navbar-brand d-flex align-items-center" href="/">
                    <i class="fas fa-shield-alt text-primary me-2"></i>Phishing Awareness Quiz
                </a>
            </div>
        </nav>

        <main class="container my-4">
            <div class="row justify-content-center">
                <div class="col-lg-8">
                    <div class="card border-0 shadow-lg mb-4 fade-in">
                        <div class="card-header p-3">
                            <h3 class="h4 mb-0">
                                <i class="fas fa-poll me-2"></i>Your Quiz Results
                            </h3>
                        </div>
                        <div class="card-body p-4 text-center">
                            <div class="stats-box mb-4 fade-in">
                                <h4 class="mb-3">Your Score</h4>
                                <div class="row">
                                    <div class="col-md-4">
                                        <p class="stats-value mb-0">{score}/{total}</p>
                                        <p class="text-muted">Questions</p>
                                    </div>
                                    <div class="col-md-4">
                                        <p class="stats-value mb-0">{percentage}%</p>
                                        <p class="text-muted">Percentage</p>
                                    </div>
                                    <div class="col-md-4">
                                        <p class="stats-value mb-0">{performance}</p>
                                        <p class="text-muted">Performance Level</p>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="alert alert-info mb-4">
                                <h4 class="alert-heading">Feedback</h4>
                                <p>{message}</p>
                            </div>
                            
                            <div class="d-grid gap-2 d-md-flex justify-content-md-center mt-4">
                                <a href="/start_quiz" class="btn btn-primary btn-lg">
                                    <i class="fas fa-redo me-2"></i>Take Quiz Again
                                </a>
                                <a href="/" class="btn btn-outline-secondary btn-lg">
                                    <i class="fas fa-home me-2"></i>Return Home
                                </a>
                            </div>
                        </div>
                    </div>
                    
                    <div class="card border-0 shadow mb-4 fade-in">
                        <div class="card-header bg-primary text-white">
                            <h3 class="h5 mb-0">
                                <i class="fas fa-check-double me-2"></i>Your Answers
                            </h3>
                        </div>
                        <div class="card-body p-4">
                            {answers_html}
                        </div>
                    </div>
                    
                    <div class="card border-0 shadow mb-4 fade-in">
                        <div class="card-header bg-primary text-white">
                            <h3 class="h5 mb-0">
                                <i class="fas fa-virus-slash me-2"></i>Real Phishing Examples
                            </h3>
                        </div>
                        <div class="card-body p-4">
                            <p class="mb-4">Here are some real-world examples of phishing attempts to help you recognize them:</p>
                            {examples_html}
                        </div>
                    </div>
                </div>
            </div>
        </main>

        <footer class="text-light py-3">
            <div class="container text-center">
                <p class="mb-0">
                    <i class="fas fa-lock me-2 text-primary"></i>Phishing Awareness Quiz - Enhancing Cybersecurity Education
                </p>
            </div>
        </footer>

        <!-- Bootstrap JavaScript Bundle -->
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    """
    return render_template_string(html)

@app.route('/reset')
def reset():
    """Reset the quiz and redirect to the home page"""
    # Clear session data
    session.clear()
    return redirect(url_for('index'))

# Entry point for the application
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)