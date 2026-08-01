from django.shortcuts import redirect
from django.contrib import messages

def future_advance_feature_required(view_func):
   
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
            
        try:
            profile = request.user.profile
            if profile.role == 'professional' and profile.is_authorized and profile.emp_id:
                return view_func(request, *args, **kwargs)
            elif profile.role == 'professional' and not profile.is_authorized:
                messages.warning(request, "आपका प्रोफेशनल वेरिफिकेशन अभी एडमिन के पास पेंडिंग है।")
                return redirect('pending_verification')
            else:
                messages.error(request, "यह एक एडवांस फीचर है। इसके लिए प्रोफेशनल अकाउंट और एडमिन अप्रूवल (Emp ID) अनिवार्य है।")
                return redirect('home')
        except AttributeError:
            messages.error(request, "कृपया पहले अपनी प्रोफाइल सेटअप पूरी करें।")
            return redirect('home')
            
    return _wrapped_view