from config import create_app
from config import db
from enrichers import enrich_indicator, export_to_misp
from models import Indicators, Requirements, Reports, Links, User, Consumers, Organization, ReportTags,RequirementReports, RequirementConsumers,Comments
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, flash, url_for, jsonify, abort, Response, send_from_directory
from flask_login import login_required, current_user
import json
from redis import Redis
import rq
from sqlalchemy import func, asc, desc

queue = rq.Queue('enricher', connection=Redis.from_url('redis://'))
from lib import add_db_entry, get_comments, time_ago,escape_jquery, get_user_info, escape_jquery, parse_indicators

main = Blueprint('main', __name__)

app = create_app()
app.app_context().push()

#these need to be imported after app is created
import reports
import requirements
import consumers
import indicators
import settings
import api


def enrich_pipeline(json_str):
    json_data=json.loads(json_str)
    indicator=json_data.get('indicator')
    org_id=json_data.get('organization')
    data=Organization.query.filter_by(id=org_id).first().__dict__
    data.pop('_sa_instance_state')
    data['indicator']=indicator
    
    enriched_data = enrich_indicator(data)
    Indicators.query.filter_by(indicator=indicator).update(enriched_data)
    db.session.flush()
    db.session.commit()

def misp_export(user_details, report,indicators):
    export_to_misp(user_details,report,indicators)

@app.route('/')
@login_required
def homepage():
    indicators = db.session.query(func.count(Indicators.id)).scalar()
    reports = db.session.query(func.count(Reports.id)).scalar()
    intel_reqs = db.session.query(func.count(Requirements.id)).scalar()

    intel_counts_by_consumer={}
    report_counts_by_consumer={}

    consumer_dict={}
    consumers_for_user=db.session.query(Consumers).join(User, User.organization==Consumers.organization).filter(User.id==current_user.id).all()
    for consumer in consumers_for_user:
        consumer_dict[consumer.id]=consumer.name

    ir_counts=db.session.query(RequirementConsumers.consumer, func.count(RequirementConsumers.requirement)).filter(RequirementConsumers.consumer.in_(consumer_dict.keys() )).group_by(RequirementConsumers.consumer).all()
    for result in ir_counts:
        intel_counts_by_consumer[result[0]]=result[1]

    report_counts=db.session.query(RequirementConsumers.consumer, func.count(RequirementReports.report)).join(RequirementReports, RequirementReports.requirement==RequirementConsumers.requirement).filter(RequirementConsumers.consumer.in_(consumer_dict.keys() )).group_by(RequirementConsumers.consumer).all()
    for result in report_counts:
        report_counts_by_consumer[result[0]]=result[1]
    
    customer_list = []
    for id in consumer_dict:
        customer_list.append({'customer': consumer_dict[id], 'reports':report_counts_by_consumer.get(id,0), 'intelreqs': intel_counts_by_consumer.get(id,0)} )

    ips = db.session.query(Indicators).filter(Indicators.indicator_type == 'IP').count()
    domains = db.session.query(Indicators).filter(Indicators.indicator_type == 'Domain').count()
    urls = db.session.query(Indicators).filter(Indicators.indicator_type == 'URL').count()
    emails = db.session.query(Indicators).filter(Indicators.indicator_type == 'Email').count()
    sha256 = db.session.query(Indicators).filter(Indicators.indicator_type == 'SHA256 Hash').count()
    md5 = db.session.query(Indicators).filter(Indicators.indicator_type == 'MD5 Hash').count()
    cve = db.session.query(Indicators).filter(Indicators.indicator_type == 'CVE').count()
    attack = db.session.query(Indicators).filter(Indicators.indicator_type == 'MITRE ATT&CK Technique').count()

    indicator_sum = ips+domains+urls+emails+sha256+md5+cve+attack

    def percentage(a, b):
        if a:
            return int(round(a / b * 100, 0)) 
        else:
            return 0

    ips = percentage(ips,indicator_sum)
    domains = percentage(domains,indicator_sum)
    urls = percentage(urls,indicator_sum)
    emails = percentage(emails,indicator_sum)
    sha256 = percentage(sha256,indicator_sum)
    md5 = percentage(md5,indicator_sum)
    cve = percentage(cve,indicator_sum)
    attack = percentage(attack,indicator_sum)


    #Not important now, but when SAAS    
    active_reqs = Requirements.query.filter(Requirements.is_archived.is_(False)).order_by(asc(Requirements.time_requirement)).limit(3).all()

    req_ids=[r.id for r in active_reqs]
    
    req_consumer_dict={}

    req_consumers=(db.session.query(Consumers,RequirementConsumers)
            .join(RequirementConsumers, Consumers.id == RequirementConsumers.consumer)            
            .filter(RequirementConsumers.requirement.in_(req_ids))
            .filter(RequirementConsumers.consumer.in_(consumer_dict.keys()))
            .order_by(asc(Consumers.name))
            .all()) 
    
    for c, r in req_consumers:
        
        c_list=req_consumer_dict.get(r.requirement, [])
        c_list.append(c.name)
        req_consumer_dict[r.requirement]=c_list
    if len(active_reqs) > 0:
        req=active_reqs[0]
        due= req.time_requirement
        if due:
            days=(due-datetime.today().date()).days
        else:
            days=0
        first_content = {}
        if days < 0:
            first_content['due_date'] = "This requirement was due %s days ago." % (str(str(days).split("-")[1]))
        elif days==0:
            first_content['due_date'] = "This requirement is due today."
        else:
            first_content['due_date'] = "This requirement is due in %s days." % (str(days))
        first_content['days'] = days
        first_content['title'] = req.title
        first_content['friendly_id'] = req.friendly_id
        first_content['id'] = req.id
        first_content['date_due'] = req.time_requirement
        first_content['title_days'] = req.time_requirement.day
        first_content['title_month'] = req.time_requirement.strftime("%b")
        first_content['consumers']=req_consumer_dict.get(req.id,[])
    else:
        first_content = None
    
    if len(active_reqs) > 1:
        req=active_reqs[1]
        due= req.time_requirement
        if due:
            days=(due-datetime.today().date()).days
        else:
            days=0
        second_content = {}
        if days < 0:
            second_content['due_date'] = "This requirement was due %s days ago." % (str(str(days).split("-")[1]))
        elif days==0:
            second_content['due_date'] = "This requirement is due today."
        else:
            second_content['due_date'] = "This requirement is due in %s days." % (str(days))
        second_content['days'] = days
        second_content['title'] = req.title
        second_content['id'] = req.id
        second_content['friendly_id'] = req.friendly_id
        second_content['date_due'] = req.time_requirement
        second_content['title_days'] = req.time_requirement.day
        second_content['title_month'] = req.time_requirement.strftime("%b")
        second_content['consumers']=req_consumer_dict.get(req.id,[])

    else:
        second_content = None


    if len(active_reqs) > 2:
        req=active_reqs[2]
        due= req.time_requirement
        if due:
            days=(due-datetime.today().date()).days
        elif days==0:
            third_content['due_date'] = "This requirement is due today."
        else:
            days=0

        third_content = {}
        if days < 0:
            third_content['due_date'] = "This requirement was due %s days ago." % (str(str(days).split("-")[1]))
        else:
            third_content['due_date'] = "This requirement is due in %s days." % (str(days))
        third_content['days'] = days
        third_content['title'] = req.title
        third_content['id'] = req.id
        third_content['friendly_id'] = req.friendly_id
        third_content['date_due'] = req.time_requirement
        third_content['title_days'] = req.time_requirement.day
        third_content['title_month'] = req.time_requirement.strftime("%b")
        third_content['consumers']=req_consumer_dict.get(req.id,[])
       
    else:
        third_content = None
     
    return render_template('homepage.html',page_title='Dashboard',indicators=indicators,reports=reports,intel_reqs=intel_reqs,customer_list=customer_list, ips=ips, domains=domains, urls=urls, emails=emails, sha256=sha256, md5=md5, cve=cve, attack=attack,first_content=first_content,second_content=second_content,third_content=third_content)

@app.route('/welcome')
@login_required
def welcome():
    User.query.filter_by(id=current_user.id).update({'new_user':0})
    db.session.commit()
    db.session.flush()
    return render_template('welcome.html')

@app.route('/export_misp/<report_id>',methods=['GET', 'POST'])
@login_required
def export_misp(report_id):
    report = Reports.query.filter_by(id=report_id).first()
    user_details = get_user_info(current_user.id)
    indicators = db.session.query(Indicators.id,Indicators.indicator,Indicators.indicator_type).join(Links, Indicators.id == Links.indicator).join(Reports, Links.report == Reports.id).filter(Reports.id == report_id).all()

    job = queue.enqueue('main.misp_export', user_details, report, indicators)

    return redirect(url_for('view_report', report_id=report.id))

def display_names(value):
    #this is the map of column names you can add as needed. 
    #CB assumed means I just guesed that this would be a good column name
    column_map={'ipinfo_hostname': "Hostname",
            'ipinfo_city' : "City",
            'ipinfo_region' : "Region",
            'ipinfo_postal' : "Postal Code",
            'ipinfo_country' : "Country",
            'ipinfo_org' : "Organization",
            'whois_registrar' : "Registrar",
            'whois_creationdate' : "Creation Date",
            'whois_expirationdate' : "Expiration Date",
            'whois_lastupdated' : "Last Updated",
            'vt_scan_date' : 'Scan Date', 
            'vt_positives' : 'Positives', 
            'last_seen' : 'Last Seen',
            'kill_chain' : 'Kill Chain',
            'av_reputation': 'Reputation',
            'av_malware_data': 'Malware Data',
            'av_url_data': 'URL Data',
            'av_passive_data': 'Passive DNS Data',
            'gn_tags': 'Tags',
            'gn_seen': 'Seen',
            'gn_classification': 'Classification',
            'gn_actor': 'Actor',
            'gn_last_seen': 'Last Seen',
            'gn_first_seen': 'First Seen',
            'hunter_result': 'Verdict',
            'hunter_score': 'Score',
            'hunter_disposable': 'Disposable',
            'hunter_webmail':'Webmail',
            'hunter_mx_records':'MX Records',
            'hunter_smtp_server':'SMTP Server',
            'hunter_smtp_check':'SMTP Check',
            'hunter_blocked':'Blocked'
        }
    #return blank if none
    if value is None:
        return ''
    # if column name is in dict, return that, else replace _ with space and title case
    else:
        return column_map.get(value, value.replace('_', ' ').title())




@app.route('/custom_search',methods=['GET'])
@login_required
def custom_search():
    query_string = request.values.get('query')

    reports_result = Reports.query.filter(Reports.content.like('%' + query_string + '%'))
    reports_result = reports_result.order_by(Reports.id).all()

    req_result = Requirements.query.filter(Requirements.summary.like('%' + query_string + '%'))
    req_result = req_result.order_by(Requirements.id).all()

    return render_template('custom_search.html', reports_result = reports_result, requirements_result = req_result)
'''
Adds a comment record from a post
obj_type= report or requirement
obj_id= id of report or requirement
user=id of user making requirement
comment= comment made
'''
@app.route('/comment/add',methods=['POST'])
@login_required
def add_comment(obj_type=None, obj_id=None, user=None, comment=None):
    
    if not obj_type:
        obj_type=request.form.get('obj_type')
    if not obj_id:
        obj_id=request.form.get('obj_id')
    if not user:
        user=request.form.get('user', current_user.id)
    if not comment:
        comment=request.form.get('comment')
    
    if obj_type and obj_id and user and comment and obj_type in ('report', 'requirement', 'req', 'indicator'):
        
        new_comment=Comments(user=user)
        new_comment.comment=comment
        if obj_type=='report':
            new_comment.report=obj_id
        elif obj_type=='requirement' or obj_type=='req':
            new_comment.requirement=obj_id
        else:
            new_comment.indicator=obj_id
        
        add_db_entry(new_comment)
        return('success')
    return('Comment insert failed.')



app.jinja_env.filters['time_ago'] = time_ago   
app.jinja_env.filters['escape_jquery'] = escape_jquery    
app.jinja_env.filters['display_names'] = display_names    

    
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
