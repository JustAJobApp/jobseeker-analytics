import re
import logging

logger = logging.getLogger(__name__)

INVALID_TITLES = {}


# Expanded levels to capture more variations.
LEVELS = {
    'Executive': [
        'ceo', 'chief executive officer', 'cxo', 'c-level', 'chief', 'founder', 'co-founder', 'president', 'vp', 'vice president',
        'executive director', 'head of', 'director', 'senior vice president', 'svp', 'chief operating officer', 'coo', 'chief technology officer',
        'cto', 'chief financial officer', 'cfo', 'chief marketing officer', 'cmo', 'chief product officer', 'cpo', 'chief information officer',
        'cio', 'chief data officer', 'cdo', 'chief compliance officer', 'cco', 'chief risk officer', 'cro', 'chief security officer', 'cso',
        'chief human resources officer', 'chro', 'chief legal officer', 'clo', 'chief strategy officer', 'cso', 'fractional'
    ],
    'Manager': [
        'manager', 'supervisor'
    ],
    'Senior': [
        'senior', 'sr', 'lead', 'principal', 'staff', 'founding', 'iv', 'v', 'iii'
    ],
    'Junior': [
        'junior', 'jr', 'entry level', 'entry-level', 'entry', 'i', 'ii', 'intern', 'internship', 'trainee', 
        'fellow', 'graduate', 'apprentice', 'co-op', 'student', 'new grad', 'new graduate'
    ]
}

# Common job role types - words that typically appear at the end of job titles
JOB_ROLE_TYPES = {
    'engineer', 'developer', 'analyst', 'manager', 'director', 'coordinator', 'specialist', 'consultant',
    'administrator', 'assistant', 'associate', 'representative', 'executive', 'officer', 'lead', 'head',
    'supervisor', 'technician', 'designer', 'architect', 'scientist', 'researcher', 'writer', 'editor',
    'marketer', 'recruiter', 'salesperson', 'accountant', 'lawyer', 'paralegal', 'nurse', 'doctor',
    'teacher', 'professor', 'instructor', 'trainer', 'planner', 'strategist', 'advisor', 'counselor',
    'therapist', 'clerk', 'secretary', 'receptionist', 'operator', 'driver', 'mechanic', 'electrician',
    'plumber', 'carpenter', 'chef', 'cook', 'server', 'bartender', 'cashier', 'teller', 'guard',
    'janitor', 'custodian', 'maintenance', 'technologist', 'programmer', 'coder', 'tester', 'auditor',
    'reviewer', 'inspector', 'investigator', 'agent', 'broker', 'trader', 'buyer', 'seller', 'merchandiser',
    'coordinator', 'facilitator', 'organizer', 'scheduler', 'dispatcher', 'controller', 'supervisor',
    'foreman', 'superintendent', 'principal', 'dean', 'provost', 'chancellor', 'president', 'ceo',
    'cfo', 'cto', 'coo', 'cmo', 'cpo', 'cio', 'intern', 'apprentice', 'trainee', 'fellow', 'employee'
}

# --- Helper and Main Functions ---

def is_job_role_word(word):
    """Check if a word is likely a job role type."""
    return word if word.lower() in JOB_ROLE_TYPES else False

def ends_with_job_role(title):
    """Check if the title ends with a recognized job role word."""
    if not title:
        return False
    words = title.strip().split()
    if not words:
        return False
    return is_job_role_word(words[-1])

def remove_numbers_and_ids(title):
    """Remove job IDs, reference numbers, and standalone numbers from job titles."""
    if not title:
        return title
    
    # Remove common job ID patterns (letters followed by numbers)
    # Examples: RD2345, JOB123, REQ456, etc.
    title = re.sub(r'\b[A-Z]{1,5}\d+\b', '', title, flags=re.IGNORECASE)  # Letter+number IDs
    
    # Remove everything after standalone numbers (experience requirements, etc.)
    # Examples: "Software Engineer 2 Years Experience" -> "Software Engineer"
    title = re.sub(r'\s+\d+.*$', '', title)  # Remove number and everything after it
    title = re.sub(r'\b\d+\b.*$', '', title)  # Remove standalone number and everything after it
    
    # Clean up extra spaces
    title = re.sub(r'\s+', ' ', title).strip()
    
    return title

def remove_seniority_levels(title):
    """Remove only Senior and Junior level indicators from a job title."""
    if not title:
        return title
    # Only remove Senior and Junior seniority levels
    seniority_phrases = []
    seniority_words = set()
    
    # Add Senior and Junior seniority levels
    for category in ['Senior', 'Junior']:
        for level in LEVELS[category]:
            level_lower = level.lower()
            if ' ' in level_lower or '-' in level_lower:
                # Multi-word phrases like "entry level" or "entry-level"
                seniority_phrases.append(level_lower)
            else:
                # Single words
                seniority_words.add(level_lower)
    
    # First remove multi-word phrases - handle entry level specially
    title = re.sub(r'\bentry\s*[-\s]\s*level\b', '', title, flags=re.IGNORECASE)
    
    # Then remove other multi-word phrases
    for phrase in seniority_phrases:
        if phrase not in ['entry level', 'entry-level']:  # Skip entry level since we handled it above
            pattern = phrase.replace(' ', r'\s+')  # Allow multiple spaces
            #logger.info("before sub title %s for pattern %s", title, r'\b' + pattern + r'\b')
            title = re.sub(r'\b' + pattern + r'\b', '', title, flags=re.IGNORECASE)
            #logger.info("after sub title %s", title)
    # Then remove single words
    words = title.split()
    filtered_words = []
    
    for word in words:
        # Clean the word of punctuation for comparison
        clean_word = re.sub(r'[^\w]', '', word.lower())
        if clean_word in words[-1].lower() or clean_word not in seniority_words:
            filtered_words.append(word)
    
    # Join back and clean up any extra spaces
    result = ' '.join(filtered_words)
    result = re.sub(r'\s+', ' ', result).strip()
    
    return result

def remove_text_after_first_dash(title):
    # Remove all text after the first dash (regular hyphen, em dash, en dash)
    space_before_dash = r'\s*\s[-–—]\s*'
    space_after_dash = r'\s*[-–—]\s\s*'
    if re.search(space_before_dash, title):
        return re.split(space_before_dash, title, 1)
    elif re.search(space_after_dash, title):
        return re.split(space_after_dash, title, 1)
    else:
        return title
    
def remove_text_after_first_slash(title):
    # Remove all text after the first dash (regular hyphen, em dash, en dash)
    space_before_slash = r'\s*\s/\s*'
    space_after_slash = r'\s*/\s\s*'
    if re.search(space_before_slash, title):
        return re.split(space_before_slash, title, 1)
    elif re.search(space_after_slash, title):
        return re.split(space_after_slash, title, 1)
    else:
        return title

def get_side_with_job_role(title: str, cat: str = "dash"):
    if cat == "dash":
        result = remove_text_after_first_dash(title)
    elif cat == "slash":
        result = remove_text_after_first_slash(title)
    if isinstance(result, list):
        parts = result # Split on first dash only
        if len(parts) == 2:
            before_dash = parts[0].strip()
            after_dash = parts[1].strip()
            
            # Check if either part contains a job role
            before_has_job_role = ends_with_job_role(before_dash)
            after_has_job_role = ends_with_job_role(after_dash)
            
            # Priority: prefer the part that ends with a job role
            if after_has_job_role and not before_has_job_role:
                title = after_dash
            elif before_has_job_role and not after_has_job_role:
                title = before_dash
            # If both or neither have job roles, check which contains more job role words
            else:
                # Clean punctuation when counting job role words
                before_job_words = sum(1 for word in before_dash.split() if is_job_role_word(re.sub(r'[^\w]', '', word)))
                after_job_words = sum(1 for word in after_dash.split() if is_job_role_word(re.sub(r'[^\w]', '', word)))
                
                if after_job_words > before_job_words:
                    title = after_dash
                elif before_job_words > after_job_words:
                    title = before_dash
                else:
                    # Default to after dash if it has job role words, otherwise before
                    title = before_dash if before_job_words > 0 else after_dash
    else:
        return result
    return title

def preprocess_title(title):
    """Cleans a raw job title string for further processing."""
    if not isinstance(title, str):
        return ""
    
    title = title.lower()
    title = re.sub(r'\[.*?\]|\(.*?\)|#.*|:.+', '', title) # More aggressive cleaning
    
    # Remove seniority levels early, before character cleaning removes hyphens
    title = remove_seniority_levels(title)
    
    # Remove all text after the first dash (regular hyphen, em dash, en dash)
    # But be smart about it - if what comes after the dash ends with a job role, keep that instead
    title = get_side_with_job_role(title, "dash")
    # Remove text after comma only if it looks like location info (keep first part)
    # Only split on comma if what comes after doesn't end with a job role
    if ',' in title:
        comma_parts = title.split(',')
        if len(comma_parts) > 1:
            # Check if any part after first comma ends with job role
            has_job_role_after_comma = any(ends_with_job_role(part.strip()) for part in comma_parts[1:])
            if not has_job_role_after_comma:
                title = comma_parts[0].strip()
            # Otherwise keep the whole title
    
    # Remove company names or anything after " at " - but only if what remains ends with a job role
    if ' at ' in title:
        title_before_at = title.split(' at ')[0].strip()
        if ends_with_job_role(title_before_at):
            title = title_before_at
        # Otherwise keep the full title including company name
    
    # Clean up remaining characters
    title = re.sub(r'[^a-z0-9\s]', '', title) # Keep only alphanumeric and spaces
    title = re.sub(r'\s+', ' ', title).strip()
    
    return title

def normalize_job_title(title):
    """
    Normalizes a raw job title into a standardized format.
    Returns a normalized string or None if the title is invalid.
    """
    if not isinstance(title, str):
        return ""

    title_lower = title.lower()
    
    # Check for invalid titles using word boundaries to avoid partial matches
    for invalid in INVALID_TITLES:
        # Use word boundaries for single words, exact match for phrases
        if len(invalid.split()) == 1:
            if re.search(r'\b' + invalid + r'\b', title_lower):
                return None
        else:
            if invalid in title_lower:
                return None

    clean_title = preprocess_title(title)
    if not clean_title:
        return None
    
    # Remove numbers and job IDs
    clean_title = remove_numbers_and_ids(clean_title)
    if not clean_title:
        return None

    # Capitalize each word in the final result
    capitalized_clean_titles = []
    for word in clean_title.split(" "):
        # If the word contains a slash, split and capitalize each part
        if "/" in word:
            parts = word.split("/")
            capitalized_parts = []
            for part in parts:
                if len(part) == 2:  # except 2 letter words like AI
                    capitalized_parts.append(part.upper())
                else:
                    capitalized_parts.append(part.title())
            capitalized_clean_titles.append("/".join(capitalized_parts))
        else:
            if len(word) == 2:
                capitalized_clean_titles.append(word.upper())
            else:
                capitalized_clean_titles.append(word.title())
    
    cleaner = " ".join(capitalized_clean_titles)
    if not ends_with_job_role(cleaner):
        return "Unknown"
    return cleaner
